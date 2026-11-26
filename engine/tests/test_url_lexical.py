"""Lexical URL checks: each finding id with positives and legitimate negatives."""

import pytest

from phishlens.findings import Finding, Severity
from phishlens.runner import run_checks
from phishlens.url.lexical import entropy, lexical_checks
from phishlens.url.parse import parse_url
from tests.fakes import make_context


async def findings(url: str) -> list[Finding]:
    return await run_checks(lexical_checks(), parse_url(url), make_context())


async def ids(url: str) -> set[str]:
    return {f.id for f in await findings(url)}


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/signin",
        "https://accounts.google.com/ServiceLogin",
        "https://login.microsoftonline.com/common/oauth2",
        "https://www.amazon.co.uk/gp/your-account",
        "http://m\N{LATIN SMALL LETTER U WITH DIAERESIS}nchen.de/",
        "https://backups.example/",
        "https://shop.example:443/basket",
        "https://www.paypal.com:443/",
    ],
)
async def test_legitimate_urls_are_not_flagged(url: str) -> None:
    assert await ids(url) == set()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("not a url", {"url.parse.invalid"}),
        ("javascript:alert(1)", {"url.scheme.dangerous"}),
        ("data:text/html;base64,PGgxPkhpPC9oMT4=", {"url.scheme.dangerous"}),
        ("http://198.51.100.7/login", {"url.host.ip_literal"}),
        ("http://2130706433/", {"url.host.ip_literal"}),
        ("http://0x7f.0.0.1/", {"url.host.ip_literal"}),
        ("http://[2001:db8::1]/", {"url.host.ip_literal"}),
        ("http://%70aypal.com/", {"url.host.percent_encoded"}),
        ("https://a.b.c.d.e.evil.example/", {"url.host.deep_subdomains"}),
        ("https://" + "a" * 40 + "." + "b" * 25 + ".example/", {"url.host.long"}),
        ("https://x7k2q9w4z8v3m1p6.example/", {"url.host.high_entropy"}),
        ("https://bit.ly/3xYzAbc", {"url.host.shortener"}),
        ("https://user@shop.example/", {"url.userinfo.present"}),
        ("https://paypal.com@evil.example/", {"url.userinfo.present"}),
        ("https://login.microsoft.com.evil.example/", {"url.brand.in_subdomain"}),
        ("https://paypal-login.evil.example/", {"url.brand.in_subdomain"}),
        ("https://evil.example/paypal/login", {"url.brand.in_path"}),
        ("https://login.evil.top/", {"url.tld.suspicious"}),
        ("https://shop.example:8443/", {"url.port.non_standard"}),
    ],
)
async def test_positives(url: str, expected: set[str]) -> None:
    assert await ids(url) == expected


async def test_userinfo_that_looks_like_a_site_is_high() -> None:
    (finding,) = await findings("https://paypal.com@evil.example/")
    assert finding.severity is Severity.HIGH
    assert "evil.example" in finding.explanation


async def test_plain_username_is_medium() -> None:
    (finding,) = await findings("https://user@shop.example/")
    assert finding.severity is Severity.MEDIUM


async def test_disguised_ip_explains_what_browsers_read() -> None:
    (finding,) = await findings("http://2130706433/")
    assert "127.0.0.1" in finding.explanation and "2130706433" in finding.explanation


async def test_brand_in_path_needs_a_login_word_for_medium() -> None:
    (login,) = await findings("https://evil.example/paypal/login")
    (news,) = await findings("https://news.example/apple-event-2026")
    assert login.severity is Severity.MEDIUM
    assert news.severity is Severity.LOW


async def test_evidence_points_into_the_original_url() -> None:
    url = "https://login.microsoft.com.evil.example/"
    (finding,) = await findings(url)
    span = finding.evidence[0].span  # type: ignore[union-attr]
    assert span is not None and url[span.start : span.end] == "login.microsoft.com"


def test_entropy() -> None:
    assert entropy("") == 0
    assert entropy("aaaa") == 0
    assert entropy("paypal") < 2.5
    assert entropy("x7k2q9w4z8v3m1p6") > 3.5
