"""URL parsing must match what a browser does, including the tricky cases."""

import ipaddress

import pytest

from phishlens.url.parse import join, parse_url


@pytest.mark.parametrize(
    ("url", "host"),
    [
        # The parser differential: a browser treats "\" as "/" here.
        ("https://evil.example\\@paypal.com/x", "evil.example"),
        ("https://paypal.com@evil.example/login", "evil.example"),
        ("https://ex\tample.com/", "example.com"),
        ("http://%70aypal.com/", "paypal.com"),
        ("HTTPS://WWW.PayPal.COM./", "www.paypal.com."),
        ("https://p\N{CYRILLIC SMALL LETTER A}ypal.com/", "xn--pypal-4ve.com"),
        ("http://münchen.de/", "xn--mnchen-3ya.de"),
    ],
)
def test_host_is_read_like_a_browser(url: str, host: str) -> None:
    assert parse_url(url).host == host


@pytest.mark.parametrize(
    ("url", "ip"),
    [
        ("http://127.0.0.1/", "127.0.0.1"),
        ("http://2130706433/", "127.0.0.1"),
        ("http://0x7f.1/", "127.0.0.1"),
        ("http://0177.0.0.1/", "127.0.0.1"),
        ("http://[::1]/", "::1"),
        ("http://[::ffff:127.0.0.1]/", "::ffff:127.0.0.1"),
    ],
)
def test_ip_forms(url: str, ip: str) -> None:
    parsed = parse_url(url)
    assert parsed.ip == ipaddress.ip_address(ip)
    assert parsed.domain is None


def test_components() -> None:
    parsed = parse_url("https://user:pw@Login.PayPal.com.evil.example:8443/a%20b?q=%41#frag")
    assert parsed.valid
    assert (parsed.scheme, parsed.username, parsed.password) == ("https", "user", "pw")
    assert (parsed.port, parsed.explicit_port) == (8443, True)
    assert parsed.path == "/a%20b" and parsed.path_decoded == "/a b"
    assert parsed.query == "q=%41" and parsed.query_decoded == "q=A"
    assert parsed.fragment == "frag"
    assert parsed.domain is not None
    assert parsed.domain.registrable == "evil.example"
    assert parsed.domain.subdomain == "login.paypal.com"
    assert parsed.raw_host == "Login.PayPal.com.evil.example"


def test_default_ports() -> None:
    assert parse_url("https://a.example/").port == 443
    assert parse_url("http://a.example/").port == 80
    assert parse_url("https://a.example:443/").explicit_port is False


def test_unicode_host_is_kept_for_display() -> None:
    assert (
        parse_url("https://xn--pypal-4ve.com/").host_unicode
        == "p\N{CYRILLIC SMALL LETTER A}ypal.com"
    )


def test_raw_host_keeps_percent_encoding() -> None:
    assert parse_url("http://%70aypal.com/").raw_host == "%70aypal.com"


def test_bare_domain_gets_a_scheme() -> None:
    parsed = parse_url("www.paypal.com/signin")
    assert parsed.scheme_added and parsed.host == "www.paypal.com"


def test_spans_point_into_the_original() -> None:
    url = "https://PAYPAL.com@evil.example/"
    span = parse_url(url).span_of("evil.example")
    assert span is not None and url[span.start : span.end] == "evil.example"


@pytest.mark.parametrize("url", ["not a url", "", "https://", "http://[::1", "\x00\x01"])
def test_invalid_urls_never_raise(url: str) -> None:
    assert parse_url(url).valid is False


def test_javascript_url_has_no_host() -> None:
    parsed = parse_url("javascript:alert(1)")
    assert parsed.valid and parsed.scheme == "javascript" and parsed.host == ""


def test_join_resolves_like_a_browser() -> None:
    assert join("https://a.example/x/y", "../z?q") == "https://a.example/z?q"
    assert join("https://a.example/", "//b.example/p") == "https://b.example/p"
