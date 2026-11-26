"""Fake services for unit tests. None of them touch the network."""

from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from phishlens.findings import CheckContext
from phishlens.net.safe_fetch import HttpResult, IPAddress
from phishlens.services import (
    DnsTemporaryError,
    Fetcher,
    RdapRecord,
    RecordType,
    UnconfiguredFetcher,
)
from phishlens.url.parse import ParsedUrl


@dataclass
class FakeDns:
    """Answers from a dict; unknown names have no records.

    Names in ``failing`` raise DnsTemporaryError, like a timeout would.
    ``lookups`` records every query, so tests can count them.
    """

    records: dict[tuple[str, RecordType], list[str]] = field(default_factory=dict)
    failing: set[tuple[str, RecordType]] = field(default_factory=set)
    lookups: list[tuple[str, RecordType]] = field(default_factory=list)

    def add(self, name: str, rdtype: RecordType, *values: str) -> "FakeDns":
        self.records.setdefault((name.lower(), rdtype), []).extend(values)
        return self

    async def resolve(self, name: str, rdtype: RecordType) -> list[str]:
        key = (name.lower().rstrip("."), rdtype)
        self.lookups.append(key)
        if key in self.failing:
            raise DnsTemporaryError("fake timeout")
        return list(self.records.get(key, []))


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
    fetcher: Fetcher | None = None,
) -> CheckContext:
    """A context made only of fakes. The HTTP client refuses every request
    unless a MockTransport with canned responses is passed in."""
    transport = http_handler or httpx.MockTransport(_refuse)
    return CheckContext(
        dns=dns or FakeDns(),
        rdap=rdap or FakeRdap(),
        http=httpx.AsyncClient(transport=transport),
        clock=clock or FixedClock(),
        fetcher=fetcher or UnconfiguredFetcher(),
    )


@dataclass
class FakeConnector:
    """Answers from a script of {url: HttpResult}; 200 with no body otherwise."""

    responses: dict[str, HttpResult] = field(default_factory=dict)
    # Every request made, as (method, url, ip, max_bytes).
    calls: list[tuple[str, str, str, int]] = field(default_factory=list)

    async def request(
        self, method: str, url: ParsedUrl, ip: IPAddress, timeout: float, max_bytes: int
    ) -> HttpResult:
        self.calls.append((method, url.href, str(ip), max_bytes))
        result = self.responses.get(url.href, HttpResult(200, {"content-type": "text/plain"}, b""))
        return HttpResult(result.status, result.headers, result.body[:max_bytes])


def redirect(to: str, status: int = 302) -> HttpResult:
    return HttpResult(status, {"location": to}, b"")
