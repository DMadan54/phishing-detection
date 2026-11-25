"""Fake services for unit tests. None of them touch the network."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from phishlens.findings import CheckContext
from phishlens.services import RdapRecord, RecordType


@dataclass
class FakeDns:
    """Answers from a dict; unknown names have no records."""

    records: dict[tuple[str, RecordType], list[str]] = field(default_factory=dict)

    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        return list(self.records.get((name.lower(), rdtype), []))


@dataclass
class FakeRdap:
    records: dict[str, RdapRecord] = field(default_factory=dict)

    async def lookup_domain(self, domain: str) -> RdapRecord | None:
        return self.records.get(domain.lower())


@dataclass
class FixedClock:
    at: datetime = datetime(2026, 1, 1, tzinfo=UTC)

    def now(self) -> datetime:
        return self.at


def _refuse(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected HTTP request in a unit test: {request.method}")


def make_context(
    *,
    dns: FakeDns | None = None,
    rdap: FakeRdap | None = None,
    http_handler: httpx.MockTransport | None = None,
    clock: FixedClock | None = None,
) -> CheckContext:
    """A context made only of fakes. The HTTP client refuses every request
    unless a MockTransport with canned responses is passed in."""
    transport = http_handler or httpx.MockTransport(_refuse)
    return CheckContext(
        dns=dns or FakeDns(),
        rdap=rdap or FakeRdap(),
        http=httpx.AsyncClient(transport=transport),
        clock=clock or FixedClock(),
    )
