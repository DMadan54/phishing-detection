import pytest

from phishlens.brands import brand_owning, brands_named_in, load_brands, load_shorteners
from phishlens.domains import (
    aligned,
    as_ip,
    domain_of_address,
    normalise_domain,
    org_domain,
    split_domain,
)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("PayPal.COM.", "paypal.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("", None),
        ("has space.example", None),
        ("a..b.example", None),
    ],
)
def test_normalise_domain(name: str, expected: str | None) -> None:
    assert normalise_domain(name) == expected


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("mail.paypal.com", "paypal.com"),
        ("paypal.com", "paypal.com"),
        ("a.b.co.uk", "b.co.uk"),
        ("co.uk", "co.uk"),
        ("alice.github.io", "alice.github.io"),
        ("paypal.com.evil.test", "evil.test"),
        ("login.microsoft.com.evil.example", "evil.example"),
        ("amazon.co.uk", "amazon.co.uk"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
        ("192.0.2.1", "192.0.2.1"),
    ],
)
def test_org_domain(domain: str, expected: str) -> None:
    assert org_domain(domain) == expected


def test_split_domain() -> None:
    parts = split_domain("login.microsoft.com.evil.example")
    assert (parts.subdomain, parts.label, parts.suffix) == (
        "login.microsoft.com",
        "evil",
        "example",
    )
    assert split_domain("accounts.google.com").label == "google"


def test_extractor_never_touches_the_network() -> None:
    # The autouse network guard would raise if tldextract tried to download.
    assert split_domain("brand-new-name.co.uk").registrable == "brand-new-name.co.uk"


def test_relaxed_alignment_allows_subdomains() -> None:
    assert aligned("bounce.mail.shop.example", "shop.example", "relaxed")
    assert not aligned("bounce.mail.shop.example", "shop.example", "strict")
    assert aligned("Shop.Example.", "shop.example", "strict")


def test_different_owners_never_align() -> None:
    assert not aligned("paypal.com.evil.test", "paypal.com", "relaxed")
    assert not aligned("alice.github.io", "mallory.github.io", "relaxed")


def test_domain_of_address() -> None:
    assert domain_of_address("Service@PayPal.com") == "paypal.com"
    assert domain_of_address("no-at-sign") is None


@pytest.mark.parametrize(
    ("host", "is_ip"), [("192.0.2.1", True), ("[2001:db8::1]", True), ("example.com", False)]
)
def test_as_ip(host: str, is_ip: bool) -> None:
    assert (as_ip(host) is not None) is is_ip


def test_brands_load() -> None:
    names = {b.name for b in load_brands()}
    assert {"PayPal", "Microsoft", "Apple"} <= names


def test_brand_owns_its_subdomains_only() -> None:
    paypal = brand_owning("www.paypal.com")
    assert paypal is not None and paypal.name == "PayPal"
    assert brand_owning("paypal.com.evil.test") is None
    assert brand_owning("notpaypal.com") is None


def test_brand_keywords_match_whole_words() -> None:
    assert [b.name for b, _ in brands_named_in("PayPal Service Team")] == ["PayPal"]
    assert brands_named_in("pineapple farm newsletter") == []
    match = brands_named_in("Your Apple ID")[0][1]
    assert match.group(0) == "Apple"


def test_shorteners_load() -> None:
    assert "bit.ly" in load_shorteners()
