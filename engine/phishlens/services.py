"""Interfaces for every outside service a check may use.

Checks never create their own DNS resolver or HTTP client. They use the ones
in the CheckContext, which means tests can hand them fakes and no unit test
depends on the real network.

Real DNS and RDAP clients arrive with the checks that need them. Until then
the Unconfigured* stand-ins fail loudly, and the runner reports that as a
check_error finding instead of crashing the request.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

RecordType = Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT"]


class ServiceNotConfiguredError(RuntimeError):
    """A check asked for a service that has no real implementation yet."""


class DnsResolver(Protocol):
    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        """Return the records of one type for a name, as text."""
        ...


@dataclass(frozen=True, slots=True)
class RdapRecord:
    """The parts of a domain's registration record that checks use."""

    domain: str
    registered: datetime | None


class RdapClient(Protocol):
    async def lookup_domain(self, domain: str) -> RdapRecord | None:
        """Return the registration record, or None if the domain has none."""
        ...


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
