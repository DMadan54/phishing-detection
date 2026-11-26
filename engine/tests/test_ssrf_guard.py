"""The SSRF guard. Every one of these must be refused before any connection.

The fake connector records every request it's asked to make, so "refused"
means the connector was never called (or never called for the bad address).
"""

import asyncio
import ipaddress
from dataclasses import dataclass, field

import pytest

from phishlens.net.safe_fetch import (
    BlockedAddressError,
    FetchPolicy,
    HttpResult,
    IPAddress,
    PinnedConnector,
    SafeFetcher,
    _PinnedBackend,
    blocked_reason,
)
from phishlens.services import RecordType
from phishlens.url.parse import ParsedUrl, parse_url
from tests.fakes import FakeDns

PUBLIC = "93.184.215.14"


@dataclass
class FakeConnector:
    """Answers from a script of {url: HttpResult}; 200 with no body otherwise."""

    responses: dict[str, HttpResult] = field(default_factory=dict)
    calls: list[tuple[str, str, str, int]] = field(
        default_factory=list
    )  # method, url, ip, max_bytes

    async def request(
        self, method: str, url: ParsedUrl, ip: IPAddress, timeout: float, max_bytes: int
    ) -> HttpResult:
        self.calls.append((method, url.href, str(ip), max_bytes))
        result = self.responses.get(url.href, HttpResult(200, {"content-type": "text/plain"}, b""))
        return HttpResult(result.status, result.headers, result.body[:max_bytes])


def redirect(to: str, status: int = 302) -> HttpResult:
    return HttpResult(status, {"location": to}, b"")


def fetcher(dns: FakeDns | None = None, connector: FakeConnector | None = None) -> SafeFetcher:
    return SafeFetcher(dns=dns or FakeDns(), connector=connector or FakeConnector())


# --- the address check -------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.10.20.30",
        "::1",
        "169.254.169.254",  # cloud metadata
        "169.254.170.2",
        "fd00:ec2::254",
        "100.100.100.200",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",  # carrier-grade NAT
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fe80::1",
        "fc00::1",
        "192.0.2.1",  # documentation range
        "240.0.0.1",  # reserved
        "::ffff:127.0.0.1",  # IPv4-mapped
        "::ffff:10.0.0.1",
        "2002:7f00:1::",  # 6to4 wrapping 127.0.0.1
        "64:ff9b::7f00:1",  # NAT64 wrapping 127.0.0.1; Python calls this one global
        "64:ff9b::a9fe:a9fe",  # NAT64 wrapping the metadata address
        "2001:0:4136:e378:8000:63bf:80ff:fffe",  # Teredo with client 127.0.0.1
    ],
)
def test_internal_addresses_are_blocked(address: str) -> None:
    assert blocked_reason(ipaddress.ip_address(address)) is not None


@pytest.mark.parametrize("address", [PUBLIC, "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address: str) -> None:
    assert blocked_reason(ipaddress.ip_address(address)) is None


def test_metadata_refusal_says_what_it_is() -> None:
    reason = blocked_reason(ipaddress.ip_address("169.254.169.254"))
    assert reason is not None and "metadata" in reason


def test_nat64_refusal_names_the_hidden_address() -> None:
    reason = blocked_reason(ipaddress.ip_address("64:ff9b::7f00:1"))
    assert reason is not None and "loopback" in reason and "hidden inside" in reason


# --- URLs that must be refused without connecting -----------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://10.1.2.3/",
        "http://[::ffff:127.0.0.1]/",
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f.1/",  # hex and short form
        "http://0177.0.0.1/",  # octal
        "http://100.64.0.1/",
        "http://[fd00:ec2::254]/",
        "http://[64:ff9b::7f00:1]/",
        "https://127.0.0.1:8443/admin",
    ],
)
async def test_internal_urls_are_refused(url: str) -> None:
    connector = FakeConnector()
    chain = await fetcher(connector=connector).follow(url)
    assert chain.stopped == "blocked"
    assert connector.calls == []


@pytest.mark.parametrize("url", ["ftp://example.com/file", "file:///etc/passwd", "gopher://x/"])
async def test_other_schemes_are_refused(url: str) -> None:
    connector = FakeConnector()
    chain = await fetcher(connector=connector).follow(url)
    assert chain.stopped == "not_http"
    assert connector.calls == []


async def test_hostname_resolving_to_a_private_ip_is_refused() -> None:
    dns = FakeDns().add("internal.attacker.example", "A", "10.0.0.5")
    connector = FakeConnector()
    chain = await fetcher(dns, connector).follow("http://internal.attacker.example/")
    assert chain.stopped == "blocked" and "10.0.0.5" in (chain.final.ip or "")
    assert connector.calls == []


async def test_one_private_answer_among_public_ones_is_refused() -> None:
    dns = FakeDns().add("mixed.attacker.example", "A", PUBLIC, "127.0.0.1")
    connector = FakeConnector()
    chain = await fetcher(dns, connector).follow("http://mixed.attacker.example/")
    assert chain.stopped == "blocked"
    assert connector.calls == []


async def test_private_ipv6_answer_is_refused() -> None:
    dns = (
        FakeDns().add("v6.attacker.example", "A", PUBLIC).add("v6.attacker.example", "AAAA", "::1")
    )
    connector = FakeConnector()
    assert (
        await fetcher(dns, connector).follow("http://v6.attacker.example/")
    ).stopped == "blocked"
    assert connector.calls == []


async def test_redirect_from_public_to_private_is_refused() -> None:
    dns = FakeDns().add("public.example", "A", PUBLIC)
    connector = FakeConnector({"http://public.example/": redirect("http://127.0.0.1/admin")})
    chain = await fetcher(dns, connector).follow("http://public.example/")
    assert chain.stopped == "blocked"
    assert [ip for _, _, ip, _ in connector.calls] == [PUBLIC]
    assert [h.url for h in chain.hops] == ["http://public.example/", "http://127.0.0.1/admin"]


async def test_redirect_to_a_name_that_resolves_privately_is_refused() -> None:
    dns = FakeDns().add("public.example", "A", PUBLIC).add("sneaky.example", "A", "169.254.169.254")
    connector = FakeConnector({"http://public.example/": redirect("http://sneaky.example/")})
    chain = await fetcher(dns, connector).follow("http://public.example/")
    assert chain.stopped == "blocked" and "metadata" in chain.detail
    assert len(connector.calls) == 1


async def test_meta_refresh_to_private_is_refused() -> None:
    page = (
        b'<html><head><meta http-equiv="refresh" content="0; url=http://10.0.0.1/"></head></html>'
    )
    dns = FakeDns().add("public.example", "A", PUBLIC)
    connector = FakeConnector(
        {"http://public.example/": HttpResult(200, {"content-type": "text/html"}, page)}
    )
    chain = await fetcher(dns, connector).follow("http://public.example/")
    assert chain.stopped == "blocked"
    assert all(ip == PUBLIC for _, _, ip, _ in connector.calls)


# --- DNS rebinding -----------------------------------------------------------


@dataclass
class RebindingDns:
    """Answers with a public address first and loopback every time after."""

    lookups: int = 0

    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        if rdtype != "A":
            return []
        self.lookups += 1
        return [PUBLIC] if self.lookups == 1 else ["127.0.0.1"]


async def test_dns_rebinding_cannot_swap_the_address() -> None:
    dns = RebindingDns()
    connector = FakeConnector()
    page = HttpResult(200, {"content-type": "text/html"}, b"<html>hi</html>")
    connector.responses["http://rebind.example/"] = page
    chain = await SafeFetcher(dns=dns, connector=connector).follow("http://rebind.example/")
    assert chain.stopped == "done"
    # Resolved once, and both requests (HEAD and GET) went to that checked IP.
    assert dns.lookups == 1
    assert [ip for _, _, ip, _ in connector.calls] == [PUBLIC, PUBLIC]


async def test_pinned_backend_rechecks_before_connecting() -> None:
    backend = _PinnedBackend(ipaddress.ip_address("127.0.0.1"), blocked_reason)
    with pytest.raises(BlockedAddressError):
        await backend.connect_tcp("innocent.example", 80)


async def test_real_connector_connects_to_the_pinned_ip_with_the_original_host() -> None:
    """A local server stands in for the site. The guard is relaxed for this test
    only, because the server has to live on loopback."""
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        connector = PinnedConnector(guard=lambda ip: None)
        url = parse_url(f"http://pinned.example:{port}/path")
        result = await connector.request("GET", url, ipaddress.ip_address("127.0.0.1"), 5, 1024)
    assert result.status == 200 and result.body == b"hello"
    assert f"Host: pinned.example:{port}".encode() in received[0]
    assert b"PhishLens" in received[0]


# --- limits ------------------------------------------------------------------


async def test_too_many_hops() -> None:
    dns = FakeDns()
    connector = FakeConnector()
    for i in range(15):
        dns.add(f"h{i}.example", "A", PUBLIC)
        connector.responses[f"http://h{i}.example/"] = redirect(f"http://h{i + 1}.example/")
    chain = await fetcher(dns, connector).follow("http://h0.example/")
    assert chain.stopped == "too_many"
    assert len(connector.calls) <= FetchPolicy().max_hops + 1


async def test_redirect_loop_is_detected() -> None:
    dns = FakeDns().add("a.example", "A", PUBLIC).add("b.example", "A", PUBLIC)
    connector = FakeConnector(
        {
            "http://a.example/": redirect("http://b.example/"),
            "http://b.example/": redirect("http://a.example/"),
        }
    )
    assert (await fetcher(dns, connector).follow("http://a.example/")).stopped == "loop"


async def test_page_reads_are_capped() -> None:
    dns = FakeDns().add("big.example", "A", PUBLIC)
    connector = FakeConnector(
        {"http://big.example/": HttpResult(200, {"content-type": "text/html"}, b"x" * 1_000_000)}
    )
    await fetcher(dns, connector).follow("http://big.example/")
    assert [(m, cap) for m, _, _, cap in connector.calls] == [("HEAD", 0), ("GET", 64 * 1024)]


@dataclass
class SlowConnector:
    async def request(
        self, method: str, url: ParsedUrl, ip: IPAddress, timeout: float, max_bytes: int
    ) -> HttpResult:
        await asyncio.sleep(10)
        raise AssertionError("unreachable")


async def test_total_time_is_capped() -> None:
    dns = FakeDns().add("slow.example", "A", PUBLIC)
    fetch = SafeFetcher(dns=dns, connector=SlowConnector(), policy=FetchPolicy(total_timeout=0.05))
    assert (await fetch.follow("http://slow.example/")).stopped == "timeout"


async def test_unknown_host_is_an_error_not_a_crash() -> None:
    chain = await fetcher().follow("http://does-not-exist.example/")
    assert chain.stopped == "error" and "doesn't exist" in chain.detail


async def test_dns_failure_is_an_error() -> None:
    dns = FakeDns(failing={("down.example", "A")})
    assert (await fetcher(dns).follow("http://down.example/")).stopped == "error"
