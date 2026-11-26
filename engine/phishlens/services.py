"""Interfaces for every outside service a check may use.

Checks never create their own DNS resolver or HTTP client. They use the ones
in the CheckContext, which means tests can hand them fakes and no unit test
depends on the real network.

The RDAP client arrives with the checks that need it. Until then the
UnconfiguredRdap stand-in fails loudly, and the runner reports that as a
check_error finding instead of crashing the request.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

import dns.asyncresolver
import dns.exception
import dns.rdata
import dns.resolver

RecordType = Literal["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"]


class ServiceNotConfiguredError(RuntimeError):
    """A check asked for a service that has no real implementation yet."""


class DnsTemporaryError(RuntimeError):
    """The lookup could not be completed (timeout, SERVFAIL, no servers).

    Different from "no such record": SPF and DMARC must report a temporary
    error here rather than treat the domain as having no policy.
    """


class DnsResolver(Protocol):
    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        """Return the records of one type for a name, as text.

        An empty list means the name or record doesn't exist. A lookup that
        couldn't be completed raises DnsTemporaryError. TXT records come
        back with their strings joined, as SPF, DKIM and DMARC expect.
        MX records come back as "<preference> <host>".
        """
        ...


class DnspythonResolver:
    """The real resolver, using dnspython's asyncio support."""

    def __init__(
        self, resolver: dns.asyncresolver.Resolver | None = None, lifetime: float = 5.0
    ) -> None:
        self._resolver = resolver or dns.asyncresolver.Resolver()
        self._lifetime = lifetime

    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        try:
            answer = await self._resolver.resolve(
                name, rdtype, lifetime=self._lifetime, search=False
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DnsTemporaryError(type(exc).__name__) from None
        except dns.exception.DNSException:
            # A name that can't exist in DNS (empty label, too long ...).
            return []
        return [rdata_to_text(rdata) for rdata in answer]


def rdata_to_text(rdata: dns.rdata.Rdata) -> str:
    """Turn one dnspython record into the text form DnsResolver promises."""
    rdtype = rdata.rdtype.name
    if rdtype == "TXT":
        # Latin-1 maps every byte to one character, so nothing is lost.
        return b"".join(rdata.strings).decode("latin-1")  # type: ignore[attr-defined]
    if rdtype in ("A", "AAAA"):
        return str(rdata.address)  # type: ignore[attr-defined]
    if rdtype == "MX":
        exchange = rdata.exchange.to_text(omit_final_dot=True)  # type: ignore[attr-defined]
        return f"{rdata.preference} {exchange}"  # type: ignore[attr-defined]
    if rdtype in ("CNAME", "NS", "PTR"):
        return str(rdata.target.to_text(omit_final_dot=True))  # type: ignore[attr-defined]
    return rdata.to_text()


@dataclass(frozen=True, slots=True)
class RdapRecord:
    """The parts of a domain's registration record that checks use."""

    domain: str
    registered: datetime | None


class RdapClient(Protocol):
    async def lookup_domain(self, domain: str) -> RdapRecord | None:
        """Return the registration record, or None if the domain has none."""
        ...


class ServiceUnavailableError(RuntimeError):
    """An outside lookup (RDAP, certificate transparency, reputation) couldn't
    give an answer. Checks report this as "unknown", never as clean."""


class CtClient(Protocol):
    async def first_certificate(self, domain: str) -> datetime | None:
        """When the first certificate for the domain was issued, according to
        certificate-transparency logs. None if no certificate is logged."""
        ...


class UnconfiguredCt:
    async def first_certificate(self, domain: str) -> datetime | None:
        raise ServiceNotConfiguredError("no certificate-transparency client is configured")


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current time, timezone-aware, in UTC."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class UnconfiguredDns:
    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        raise ServiceNotConfiguredError("no DNS resolver is configured")


class UnconfiguredRdap:
    async def lookup_domain(self, domain: str) -> RdapRecord | None:
        raise ServiceNotConfiguredError("no RDAP client is configured")


# --- following redirects -----------------------------------------------------
# The real Fetcher is phishlens.net.safe_fetch.SafeFetcher.

HopKind = Literal["start", "http", "meta_refresh", "script"]
StopReason = Literal["done", "blocked", "too_many", "error", "loop", "not_http", "timeout"]


@dataclass(frozen=True, slots=True)
class Hop:
    url: str
    kind: HopKind  # how we got here
    status: int | None = None
    ip: str | None = None


@dataclass(frozen=True, slots=True)
class RedirectChain:
    hops: tuple[Hop, ...]
    stopped: StopReason
    detail: str = ""  # for blocked and error: what happened, in plain words

    @property
    def final(self) -> Hop:
        return self.hops[-1]


class Fetcher(Protocol):
    async def follow(self, url: str) -> RedirectChain: ...


class UnconfiguredFetcher:
    async def follow(self, url: str) -> RedirectChain:
        raise ServiceNotConfiguredError("no fetcher is configured")
