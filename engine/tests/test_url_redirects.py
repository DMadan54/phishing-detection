"""The redirect-chain check, run through the real SafeFetcher with a fake network."""

from phishlens.findings import Finding, LookalikeEvidence, Severity
from phishlens.net.safe_fetch import HttpResult, SafeFetcher
from phishlens.runner import run_checks
from phishlens.url.lookalike import BrandLookalikes
from phishlens.url.parse import parse_url
from phishlens.url.redirects import RedirectCheck
from tests.fakes import FakeConnector, FakeDns, make_context, redirect

PUBLIC = "93.184.215.14"


def html(body: str) -> HttpResult:
    return HttpResult(200, {"content-type": "text/html"}, body.encode())


async def findings(start: str, dns: FakeDns, connector: FakeConnector) -> dict[str, Finding]:
    ctx = make_context(fetcher=SafeFetcher(dns=dns, connector=connector))
    check = RedirectCheck(BrandLookalikes())
    return {f.id: f for f in await run_checks([check], parse_url(start), ctx)}


def world(*hosts: str) -> FakeDns:
    dns = FakeDns()
    for host in hosts:
        dns.add(host, "A", PUBLIC)
    return dns


async def test_no_redirect_means_no_findings() -> None:
    dns = world("shop.example")
    assert await findings("https://shop.example/", dns, FakeConnector()) == {}


async def test_shortener_to_lookalike() -> None:
    dns = world("bit.ly", "track.example", "paypa1.com")
    connector = FakeConnector(
        {
            "https://bit.ly/abc": redirect("https://track.example/c?id=1", 301),
            "https://track.example/c?id=1": redirect("https://bit.ly/def"),
            "https://bit.ly/def": redirect("https://paypa1.com/signin"),
        }
    )
    found = await findings("https://bit.ly/abc", dns, connector)
    assert set(found) == {
        "url.redirect.chain",
        "url.redirect.shortener",
        "url.redirect.to_lookalike",
    }
    lookalike = found["url.redirect.to_lookalike"]
    assert lookalike.severity is Severity.HIGH
    assert "paypa1.com" in lookalike.explanation and "paypal.com" in lookalike.explanation
    assert any(isinstance(e, LookalikeEvidence) for e in lookalike.evidence)
    hops = [e.excerpt for e in found["url.redirect.chain"].evidence]  # type: ignore[union-attr]
    assert hops[0].startswith("1. 301 https://bit.ly/abc")
    assert hops[-1].startswith("4. 200 https://paypa1.com/signin")


async def test_meta_refresh_is_followed_and_flagged() -> None:
    dns = world("wait.example", "dest.example")
    page = '<meta http-equiv="Refresh" content="2; URL=https://dest.example/x">'
    connector = FakeConnector({"https://wait.example/": html(page)})
    found = await findings("https://wait.example/", dns, connector)
    assert set(found) == {"url.redirect.chain", "url.redirect.meta_refresh"}


async def test_script_redirect_is_read_never_run() -> None:
    dns = world("wait.example", "dest.example")
    page = "<script>window.location.href = 'https://dest.example/y';</script>"
    connector = FakeConnector({"https://wait.example/": html(page)})
    found = await findings("https://wait.example/", dns, connector)
    assert set(found) == {"url.redirect.chain", "url.redirect.script"}
    assert "never run" in found["url.redirect.script"].explanation


async def test_redirect_to_internal_address_is_reported() -> None:
    dns = world("public.example")
    connector = FakeConnector({"https://public.example/": redirect("http://169.254.169.254/")})
    found = await findings("https://public.example/", dns, connector)
    assert set(found) == {"url.redirect.chain", "url.redirect.blocked"}
    assert "metadata" in found["url.redirect.blocked"].explanation


async def test_loops_count_as_too_many() -> None:
    dns = world("a.example", "b.example")
    connector = FakeConnector(
        {
            "https://a.example/": redirect("https://b.example/"),
            "https://b.example/": redirect("https://a.example/"),
        }
    )
    found = await findings("https://a.example/", dns, connector)
    assert "url.redirect.too_many" in found
    assert "circle" in found["url.redirect.too_many"].explanation


async def test_unreachable_site_is_informational() -> None:
    found = await findings("https://gone.example/", FakeDns(), FakeConnector())
    assert set(found) == {"url.redirect.error"}
    assert found["url.redirect.error"].severity is Severity.INFO


async def test_same_owner_hops_are_not_lookalikes() -> None:
    dns = world("paypal.com", "www.paypal.com")
    connector = FakeConnector({"https://paypal.com/": redirect("https://www.paypal.com/")})
    found = await findings("https://paypal.com/", dns, connector)
    assert set(found) == {"url.redirect.chain"}


async def test_non_web_urls_are_not_followed() -> None:
    assert await findings("javascript:alert(1)", FakeDns(), FakeConnector()) == {}
