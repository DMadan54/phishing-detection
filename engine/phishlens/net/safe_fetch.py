"""Fetch a user-supplied URL without letting it reach anything internal.

SSRF (server-side request forgery) is making a server fetch something it
shouldn't: an admin page on localhost, a database on the private network, or
the cloud metadata service at 169.254.169.254, which hands out the server's
own credentials. Anything that follows a URL someone else supplied is a way
in, and every redirect is a new URL. So, before EVERY request:

1. Only http and https are allowed.
2. The host is resolved, and every address it resolves to is checked. Anything
   that isn't a public internet address is refused: loopback, private ranges,
   link-local (which includes the metadata service), carrier-grade NAT,
   multicast, reserved and documentation ranges. IPv6 addresses that embed
   an IPv4 address (IPv4-mapped ::ffff:a.b.c.d, 6to4, Teredo and NAT64) are
   unwrapped and the embedded address is checked too. Python itself reports
   NAT64's 64:ff9b::7f00:1 (that is, 127.0.0.1) as "global", so relying on
   is_global alone would let it through.
3. The connection is made to the exact IP that was checked. Otherwise an
   attacker's DNS server could answer "public address" when we check and
   "127.0.0.1" a moment later when we connect (DNS rebinding). The hostname
   is still used for TLS certificate checks and the Host header, so HTTPS
   works normally.
4. Limits: at most 10 hops, 5 seconds per hop, 20 seconds in total, and only
   the first 64 KB of a page is read.

HTML is only read as text, to spot <meta http-equiv="refresh"> and literal
"location = ..." redirects. Nothing is ever executed.
"""

import asyncio
import ipaddress
import re
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

import httpcore

from phishlens.services import (
    DnsResolver,
    DnsTemporaryError,
    Hop,
    HopKind,
    RedirectChain,
)
from phishlens.url.parse import ParsedUrl, join, parse_url

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Generic on purpose: the sites fetched are often run by attackers, so nothing
# here identifies who is running PhishLens.
USER_AGENT = "Mozilla/5.0 (compatible; PhishLens/0.1)"

# Metadata services of the big clouds. All are already non-public addresses;
# they're named so the refusal can say exactly what was being reached.
METADATA = {
    ipaddress.ip_address(
        "169.254.169.254"
    ): "a cloud metadata service (AWS, Azure, GCP and others)",
    ipaddress.ip_address("169.254.170.2"): "the AWS container credentials service",
    ipaddress.ip_address("fd00:ec2::254"): "the AWS metadata service (IPv6)",
    ipaddress.ip_address("100.100.100.200"): "the Alibaba Cloud metadata service",
    ipaddress.ip_address("192.0.0.192"): "the Oracle Cloud metadata service",
}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


# --- the address check -------------------------------------------------------


def embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address hidden inside an IPv6 one, if any."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]  # the client address
    if any(ip in net for net in NAT64):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def blocked_reason(ip: IPAddress) -> str | None:
    """Why this address must not be contacted, or None if it's public."""
    if ip in METADATA:
        return METADATA[ip]
    if isinstance(ip, ipaddress.IPv6Address):
        inner = embedded_ipv4(ip)
        if inner is not None:
            reason = blocked_reason(inner)
            if reason:
                return f"{reason} (hidden inside the IPv6 address {ip})"
    if ip.is_loopback:
        return "this machine (loopback)"
    if ip.is_link_local:
        return "a link-local address"
    if isinstance(ip, ipaddress.IPv4Address) and ip in CGNAT:
        return "a carrier-grade NAT address"
    if ip.is_private:
        return "a private network address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_unspecified or ip.is_reserved or not ip.is_global:
        return "an address that isn't on the public internet"
    return None


class BlockedAddressError(Exception):
    def __init__(self, host: str, ip: IPAddress, reason: str) -> None:
        super().__init__(f"{host} -> {ip}: {reason}")
        self.host, self.ip, self.reason = host, ip, reason


# --- connecting --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    headers: Mapping[str, str]  # lower-case names
    body: bytes  # at most max_bytes


class Connector(Protocol):
    async def request(
        self, method: str, url: ParsedUrl, ip: IPAddress, timeout: float, max_bytes: int
    ) -> HttpResult: ...


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connects to one checked IP whatever hostname the request names."""

    def __init__(self, ip: IPAddress, guard: "AddressGuard") -> None:
        self._ip = ip
        self._guard = guard
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.AsyncNetworkStream:
        # Checked again right before connecting, as a second line of defence.
        reason = self._guard(self._ip)
        if reason:
            raise BlockedAddressError(host, self._ip, reason)
        return await self._inner.connect_tcp(str(self._ip), port, timeout=timeout)

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: object = None
    ) -> httpcore.AsyncNetworkStream:
        raise BlockedAddressError(path, ipaddress.IPv4Address(0), "a local socket")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class AddressGuard(Protocol):
    def __call__(self, ip: IPAddress) -> str | None: ...


class PinnedConnector:
    """The real connector: httpcore, pinned to the checked IP."""

    def __init__(self, guard: AddressGuard = blocked_reason) -> None:
        self._guard = guard
        self._ssl = ssl.create_default_context()

    async def request(
        self, method: str, url: ParsedUrl, ip: IPAddress, timeout: float, max_bytes: int
    ) -> HttpResult:
        default = {"http": 80, "https": 443}[url.scheme]
        host_header = url.host if url.port == default else f"{url.host}:{url.port}"
        if isinstance(url.ip, ipaddress.IPv6Address):
            host_header = f"[{url.host}]" + ("" if url.port == default else f":{url.port}")
        headers = [
            (b"Host", host_header.encode()),
            (b"User-Agent", USER_AGENT.encode()),
            (b"Accept", b"text/html,*/*;q=0.5"),
        ]
        timeouts = {"connect": timeout, "read": timeout, "write": timeout, "pool": timeout}
        backend = _PinnedBackend(ip, self._guard)
        async with (
            httpcore.AsyncConnectionPool(
                ssl_context=self._ssl, network_backend=backend, max_connections=1, retries=0
            ) as pool,
            pool.stream(
                method, url.href, headers=headers, extensions={"timeout": timeouts}
            ) as response,
        ):
            body = b""
            if method != "HEAD":
                async for chunk in response.aiter_stream():
                    body += chunk
                    if len(body) >= max_bytes:
                        body = body[:max_bytes]
                        break
            names = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in response.headers}
            return HttpResult(response.status, names, body)


# --- following a chain -------------------------------------------------------

_META_REFRESH = re.compile(
    rb"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d*\s*;?\s*url\s*=\s*['"]?([^"'>\s]+)""",
    re.IGNORECASE,
)
_SCRIPT_REDIRECT = re.compile(
    rb"""(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']"""
    rb"""|location\.(?:replace|assign)\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FetchPolicy:
    max_hops: int = 10
    hop_timeout: float = 5.0
    total_timeout: float = 20.0
    max_bytes: int = 64 * 1024
    schemes: frozenset[str] = frozenset({"http", "https"})


@dataclass
class SafeFetcher:
    dns: DnsResolver
    connector: Connector = field(default_factory=PinnedConnector)
    policy: FetchPolicy = field(default_factory=FetchPolicy)
    guard: AddressGuard = blocked_reason

    async def follow(self, url: str) -> RedirectChain:
        hops: list[Hop] = []
        try:
            async with asyncio.timeout(self.policy.total_timeout):
                return await self._follow(url, hops)
        except TimeoutError:
            return RedirectChain(tuple(hops) or (Hop(url, "start"),), "timeout", "took too long")

    async def _follow(self, start: str, hops: list[Hop]) -> RedirectChain:
        current = start
        kind: HopKind = "start"
        seen: set[str] = set()
        while True:
            parsed = parse_url(current)
            if not parsed.valid or parsed.scheme not in self.policy.schemes:
                hops.append(Hop(current, kind))
                return RedirectChain(tuple(hops), "not_http", f"{parsed.scheme or 'unknown'}: link")
            if parsed.href in seen:
                return RedirectChain(tuple(hops), "loop", "the redirects go round in a circle")
            seen.add(parsed.href)
            if len(hops) > self.policy.max_hops:
                return RedirectChain(tuple(hops), "too_many", f"more than {self.policy.max_hops}")

            try:
                ip = await self._checked_ip(parsed)
            except BlockedAddressError as exc:
                hops.append(Hop(parsed.href, kind, ip=str(exc.ip)))
                return RedirectChain(tuple(hops), "blocked", f"{exc.host} is {exc.reason}")
            except DnsTemporaryError:
                hops.append(Hop(parsed.href, kind))
                return RedirectChain(tuple(hops), "error", f"{parsed.host} couldn't be looked up")
            if ip is None:
                hops.append(Hop(parsed.href, kind))
                return RedirectChain(tuple(hops), "error", f"{parsed.host} doesn't exist")

            try:
                result, next_url, next_kind = await self._step(parsed, ip)
            except BlockedAddressError as exc:
                hops.append(Hop(parsed.href, kind, ip=str(ip)))
                return RedirectChain(tuple(hops), "blocked", f"{exc.host} is {exc.reason}")
            except (httpcore.TimeoutException, TimeoutError):
                hops.append(Hop(parsed.href, kind, ip=str(ip)))
                return RedirectChain(tuple(hops), "error", f"{parsed.host} didn't answer in time")
            except (httpcore.NetworkError, httpcore.ProtocolError, ssl.SSLError, OSError) as exc:
                hops.append(Hop(parsed.href, kind, ip=str(ip)))
                return RedirectChain(
                    tuple(hops),
                    "error",
                    f"{parsed.host} couldn't be reached ({type(exc).__name__})",
                )

            hops.append(Hop(parsed.href, kind, result.status, str(ip)))
            if next_url is None:
                return RedirectChain(tuple(hops), "done")
            current, kind = next_url, next_kind

    async def _checked_ip(self, url: ParsedUrl) -> IPAddress | None:
        """Resolve once and check every answer. One bad answer refuses the host,
        so a name can't hide an internal address behind a public one."""
        if url.ip is not None:
            candidates: Sequence[IPAddress] = [url.ip]
        else:
            answers = [
                *await self.dns.resolve(url.host, "A"),
                *await self.dns.resolve(url.host, "AAAA"),
            ]
            candidates = [ipaddress.ip_address(a) for a in answers]
        for ip in candidates:
            reason = self.guard(ip)
            if reason:
                raise BlockedAddressError(url.host, ip, reason)
        return candidates[0] if candidates else None

    async def _step(self, url: ParsedUrl, ip: IPAddress) -> tuple[HttpResult, str | None, HopKind]:
        timeout = self.policy.hop_timeout
        head = await self.connector.request("HEAD", url, ip, timeout, 0)
        if head.status in REDIRECT_STATUSES and "location" in head.headers:
            return head, join(url.href, head.headers["location"]), "http"
        result = head
        if (
            head.status in (405, 501)
            or "html" in head.headers.get("content-type", "")
            or head.status >= 400
        ):
            result = await self.connector.request("GET", url, ip, timeout, self.policy.max_bytes)
            if result.status in REDIRECT_STATUSES and "location" in result.headers:
                return result, join(url.href, result.headers["location"]), "http"
        meta = _META_REFRESH.search(result.body)
        if meta:
            target = meta.group(1).decode("latin-1")
            return result, join(url.href, target), "meta_refresh"
        script = _SCRIPT_REDIRECT.search(result.body)
        if script:
            target = (script.group(1) or script.group(2)).decode("latin-1")
            return result, join(url.href, target), "script"
        return result, None, "http"
