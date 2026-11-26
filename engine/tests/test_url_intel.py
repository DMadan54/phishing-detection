"""Domain age, certificate history and reputation, with every service faked."""

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from phishlens.findings import Severity
from phishlens.intel.cache import RateLimiter, TtlCache
from phishlens.intel.ct import CrtShClient
from phishlens.intel.rdap import HttpRdapClient, bootstrap, registration_date
from phishlens.intel.reputation import SafeBrowsing, UrlScan, VirusTotal
from phishlens.runner import run_checks
from phishlens.services import RdapRecord, ServiceUnavailableError
from phishlens.url.intel_checks import AgeCheck, CertificateCheck, ReputationCheck
from phishlens.url.parse import parse_url
from tests.fakes import FakeRdap, FixedClock, make_context

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
CLOCK = FixedClock(NOW)


def client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler)


def recorder(
    responses: dict[str, httpx.Response],
) -> tuple[list[httpx.Request], httpx.MockTransport]:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        for prefix, response in responses.items():
            if str(request.url).startswith(prefix):
                return response
        return httpx.Response(500)

    return seen, httpx.MockTransport(handle)


# --- cache and rate limiter --------------------------------------------------


def test_cache_expires() -> None:
    clock = FixedClock(NOW)
    cache: TtlCache[str, int] = TtlCache(clock, timedelta(minutes=5))
    cache.put("a", 1)
    assert cache.get("a") == 1
    clock.at = NOW + timedelta(minutes=6)
    assert cache.get("a") is None


def test_cache_is_bounded() -> None:
    cache: TtlCache[int, int] = TtlCache(CLOCK, timedelta(hours=1), max_items=2)
    for i in range(3):
        cache.put(i, i)
    assert cache.get(0) is None and cache.get(2) == 2


async def test_rate_limiter_spaces_calls_and_gives_up() -> None:
    now = [0.0]
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(interval=5, max_wait=5, now=lambda: now[0], sleep=sleep)
    assert await limiter.acquire() and await limiter.acquire()
    assert waits == [5]
    limiter_busy = RateLimiter(interval=10, max_wait=5, now=lambda: now[0], sleep=sleep)
    assert await limiter_busy.acquire()
    assert await limiter_busy.acquire() is False


# --- RDAP --------------------------------------------------------------------


def test_bootstrap_snapshot_is_shipped() -> None:
    servers = bootstrap()
    assert servers["com"].startswith("https://") and servers["com"].endswith("/")
    assert "uk" in servers


def test_registration_date() -> None:
    record = {
        "events": [
            {"eventAction": "last changed", "eventDate": "2026-11-25T00:00:00Z"},
            {"eventAction": "registration", "eventDate": "2026-11-23T08:30:00Z"},
        ]
    }
    assert registration_date(record) == datetime(2026, 11, 23, 8, 30, tzinfo=UTC)
    assert registration_date({}) is None


async def test_rdap_client_asks_the_right_server_once() -> None:
    body = {"events": [{"eventAction": "registration", "eventDate": "2026-11-23T00:00:00Z"}]}
    seen, transport = recorder({"https://rdap.test/": httpx.Response(200, json=body)})
    rdap = HttpRdapClient(client(transport), CLOCK, servers={"example": "https://rdap.test/"})
    for _ in range(2):
        record = await rdap.lookup_domain("login.newsite.example")
        assert record == RdapRecord("newsite.example", datetime(2026, 11, 23, tzinfo=UTC))
    assert [str(r.url) for r in seen] == ["https://rdap.test/domain/newsite.example"]
    assert seen[0].headers["accept"] == "application/rdap+json"


async def test_rdap_not_found_is_cached_as_none() -> None:
    seen, transport = recorder({"https://rdap.test/": httpx.Response(404)})
    rdap = HttpRdapClient(client(transport), CLOCK, servers={"example": "https://rdap.test/"})
    assert await rdap.lookup_domain("gone.example") is None
    assert await rdap.lookup_domain("gone.example") is None
    assert len(seen) == 1


@pytest.mark.parametrize("response", [httpx.Response(503), httpx.Response(200, text="not json")])
async def test_rdap_failures_are_unavailable(response: httpx.Response) -> None:
    _, transport = recorder({"https://rdap.test/": response})
    rdap = HttpRdapClient(client(transport), CLOCK, servers={"example": "https://rdap.test/"})
    with pytest.raises(ServiceUnavailableError):
        await rdap.lookup_domain("x.example")


async def test_rdap_without_a_server_is_unavailable() -> None:
    rdap = HttpRdapClient(
        client(httpx.MockTransport(lambda r: httpx.Response(500))), CLOCK, servers={}
    )
    with pytest.raises(ServiceUnavailableError, match="no RDAP server"):
        await rdap.lookup_domain("x.de")


# --- the age check -----------------------------------------------------------


async def age_findings(url: str, rdap: FakeRdap) -> dict[str, object]:
    ctx = make_context(rdap=rdap, clock=CLOCK)
    return {f.id: f for f in await run_checks([AgeCheck()], parse_url(url), ctx)}


async def test_three_day_old_domain_is_high() -> None:
    rdap = FakeRdap({"newsite.example": RdapRecord("newsite.example", NOW - timedelta(days=3))})
    found = await age_findings("https://login.newsite.example/", rdap)
    finding = found["url.age.new"]
    assert finding.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert finding.title == "Registered 3 days ago"  # type: ignore[attr-defined]


async def test_three_week_old_domain_is_medium() -> None:
    rdap = FakeRdap({"newsite.example": RdapRecord("newsite.example", NOW - timedelta(days=21))})
    found = await age_findings("https://newsite.example/", rdap)
    assert found["url.age.new"].severity is Severity.MEDIUM  # type: ignore[attr-defined]


async def test_old_domain_is_quiet() -> None:
    rdap = FakeRdap({"oldsite.example": RdapRecord("oldsite.example", NOW - timedelta(days=4000))})
    assert await age_findings("https://oldsite.example/", rdap) == {}


async def test_unknown_age_is_informational() -> None:
    found = await age_findings("https://nowhere.example/", FakeRdap())
    assert set(found) == {"url.age.unknown"}


@pytest.mark.parametrize("url", ["https://www.paypal.com/", "http://198.51.100.7/"])
async def test_brand_domains_and_ips_are_not_looked_up(url: str) -> None:
    assert await age_findings(url, FakeRdap()) == {}


# --- certificate transparency ------------------------------------------------


def crtsh(*dates: str) -> httpx.Response:
    return httpx.Response(200, json=[{"not_before": d} for d in dates])


async def test_crtsh_returns_the_earliest_certificate() -> None:
    seen, transport = recorder(
        {"https://crt.sh/": crtsh("2026-11-25T10:00:00", "2026-11-24T09:00:00")}
    )
    ct = CrtShClient(client(transport), CLOCK, RateLimiter(0, 0, now=lambda: 0.0))
    assert await ct.first_certificate("www.newsite.example") == datetime(
        2026, 11, 24, 9, tzinfo=UTC
    )
    assert seen[0].url.params["q"] == "newsite.example"
    await ct.first_certificate("newsite.example")
    assert len(seen) == 1  # cached


async def test_crtsh_with_no_certificates() -> None:
    _, transport = recorder({"https://crt.sh/": httpx.Response(200, json=[])})
    ct = CrtShClient(client(transport), CLOCK, RateLimiter(0, 0, now=lambda: 0.0))
    assert await ct.first_certificate("fresh.example") is None


async def test_crtsh_rate_limit_means_unknown() -> None:
    _, transport = recorder({"https://crt.sh/": crtsh("2020-01-01T00:00:00")})
    ct = CrtShClient(client(transport), CLOCK, RateLimiter(60, 0, now=lambda: 0.0))
    await ct.first_certificate("a.example")
    with pytest.raises(ServiceUnavailableError, match="rate limit"):
        await ct.first_certificate("b.example")


@dataclass
class FakeCt:
    first: dict[str, datetime] = field(default_factory=dict)
    fail: bool = False

    async def first_certificate(self, domain: str) -> datetime | None:
        if self.fail:
            raise ServiceUnavailableError("down")
        return self.first.get(domain)


async def ct_ids(url: str, ct: FakeCt) -> set[str]:
    ctx = make_context(clock=CLOCK)
    ctx = type(ctx)(dns=ctx.dns, rdap=ctx.rdap, http=ctx.http, clock=ctx.clock, ct=ct)
    return {f.id for f in await run_checks([CertificateCheck()], parse_url(url), ctx)}


async def test_brand_new_certificate() -> None:
    ct = FakeCt({"newsite.example": NOW - timedelta(days=2)})
    assert await ct_ids("https://newsite.example/login", ct) == {"url.ct.first_seen_recent"}


async def test_old_certificate_is_quiet() -> None:
    assert (
        await ct_ids("https://old.example/", FakeCt({"old.example": NOW - timedelta(days=900)}))
        == set()
    )


async def test_certificate_lookup_failure_is_unknown() -> None:
    assert await ct_ids("https://x.example/", FakeCt(fail=True)) == {"url.ct.unknown"}


async def test_plain_http_has_no_certificate_check() -> None:
    assert await ct_ids("http://x.example/", FakeCt()) == set()


# --- reputation --------------------------------------------------------------


async def test_safe_browsing_match() -> None:
    body = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    seen, transport = recorder(
        {"https://safebrowsing.googleapis.com/": httpx.Response(200, json=body)}
    )
    source = SafeBrowsing(client(transport), CLOCK, "k")
    verdict = await source.lookup(parse_url("https://evil.example/login"))
    assert verdict is not None and "phishing" in verdict.summary
    sent = json.loads(seen[0].content)
    assert sent["threatInfo"]["threatEntries"] == [{"url": "https://evil.example/login"}]
    assert seen[0].url.params["key"] == "k"


async def test_safe_browsing_no_match() -> None:
    _, transport = recorder({"https://safebrowsing.googleapis.com/": httpx.Response(200, json={})})
    assert (
        await SafeBrowsing(client(transport), CLOCK, "k").lookup(parse_url("https://ok.example/"))
        is None
    )


async def test_urlscan_only_searches() -> None:
    seen, transport = recorder(
        {"https://urlscan.io/api/v1/search/": httpx.Response(200, json={"total": 3})}
    )
    verdict = await UrlScan(client(transport), CLOCK, "k").lookup(
        parse_url("https://evil.example/")
    )
    assert verdict is not None and "3 earlier scan(s)" in verdict.summary
    assert all(r.method == "GET" and "/search/" in str(r.url) for r in seen)
    assert seen[0].headers["api-key"] == "k"


async def test_virustotal_report_lookup() -> None:
    url = "https://evil.example/"
    ident = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    stats = {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 10}
    body = {"data": {"attributes": {"last_analysis_stats": stats}}}
    seen, transport = recorder(
        {f"https://www.virustotal.com/api/v3/urls/{ident}": httpx.Response(200, json=body)}
    )
    verdict = await VirusTotal(client(transport), CLOCK, "k").lookup(parse_url(url))
    assert verdict is not None and verdict.severity is Severity.HIGH
    assert "5 of 76" in verdict.summary
    assert seen[0].method == "GET" and seen[0].headers["x-apikey"] == "k"


async def test_virustotal_never_seen_is_not_clean_but_silent() -> None:
    _, transport = recorder({"https://www.virustotal.com/": httpx.Response(404)})
    assert (
        await VirusTotal(client(transport), CLOCK, "k").lookup(parse_url("https://new.example/"))
        is None
    )


async def test_reputation_findings_name_their_source() -> None:
    body = {"matches": [{"threatType": "MALWARE"}]}
    _, transport = recorder(
        {"https://safebrowsing.googleapis.com/": httpx.Response(200, json=body)}
    )
    _, failing = recorder({})
    check = ReputationCheck(
        (SafeBrowsing(client(transport), CLOCK, "k"), UrlScan(client(failing), CLOCK, "k"))
    )
    findings = await run_checks([check], parse_url("https://evil.example/"), make_context())
    assert [f.id for f in findings] == ["url.reputation.safe_browsing"]
    assert findings[0].title == "Flagged by Google Safe Browsing"


async def test_no_keys_means_no_lookups() -> None:
    assert (
        await run_checks([ReputationCheck()], parse_url("https://evil.example/"), make_context())
        == []
    )
