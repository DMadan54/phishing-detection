"""Lookalike detection. The shared vectors are the contract with the extension."""

import json
from pathlib import Path
from typing import Any

import pytest

from phishlens.findings import Check, LookalikeEvidence, Severity
from phishlens.runner import run_checks
from phishlens.url.domain_checks import IdnCheck, LookalikeCheck
from phishlens.url.lookalike import (
    BrandLookalikes,
    differences,
    edit_distance,
    keyboard_adjacent,
    load_popular,
)
from phishlens.url.parse import ParsedUrl, parse_url
from phishlens.url.unicode_data import is_mixed_script, skeleton
from tests.fakes import make_context

VECTORS: dict[str, Any] = json.loads(
    (Path(__file__).parents[2] / "shared" / "test-vectors" / "lookalike.json").read_text()
)
DETECTOR = BrandLookalikes(popular=frozenset(VECTORS["popular"]))


@pytest.mark.parametrize("vector", VECTORS["lookalike"], ids=lambda v: v["domain"])
def test_lookalike_vectors(vector: dict[str, Any]) -> None:
    match = DETECTOR.check(vector["domain"])
    expected = vector["expect"]
    if expected is None:
        assert match is None, f"{vector['domain']} should not match: {vector['why']}"
    else:
        assert match is not None, f"{vector['domain']} should match: {vector['why']}"
        assert (match.rule, match.brand.name) == (expected["rule"], expected["brand"])


@pytest.mark.parametrize("vector", VECTORS["skeleton"], ids=lambda v: f"{v['a']}-{v['b']}")
def test_skeleton_vectors(vector: dict[str, Any]) -> None:
    assert (skeleton(vector["a"]) == skeleton(vector["b"])) is vector["same"]


@pytest.mark.parametrize("vector", VECTORS["mixed_script"], ids=lambda v: v["why"])
def test_mixed_script_vectors(vector: dict[str, Any]) -> None:
    assert is_mixed_script(vector["label"]) is vector["mixed"]


def test_every_rule_has_a_vector() -> None:
    rules = {v["expect"]["rule"] for v in VECTORS["lookalike"] if v["expect"]}
    assert rules == {"homograph", "character_swap", "tld_swap", "typo", "combo"}


# --- building blocks ---------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "distance"),
    [
        ("paypal", "paypal", 0),
        ("paypla", "paypal", 1),  # neighbouring letters swapped counts once
        ("paypall", "paypal", 1),
        ("payal", "paypal", 1),
        ("paypak", "paypal", 1),
        ("pyapla", "paypal", 2),
        ("", "abc", 3),
    ],
)
def test_edit_distance(a: str, b: str, distance: int) -> None:
    assert edit_distance(a, b) == distance


def test_keyboard_adjacency() -> None:
    assert (
        keyboard_adjacent("k", "l") and keyboard_adjacent("q", "w") and keyboard_adjacent("g", "y")
    )
    assert not keyboard_adjacent("a", "l")


def test_differences_name_the_characters() -> None:
    (change,) = differences("p\N{CYRILLIC SMALL LETTER A}ypal.com", "paypal.com")
    assert (change.position, change.genuine) == (1, "a")
    assert change.description == "CYRILLIC SMALL LETTER A instead of LATIN SMALL LETTER A"


def test_multi_letter_differences() -> None:
    (change,) = differences("rnicrosoft.com", "microsoft.com")
    assert (change.seen, change.genuine) == ("rn", "m")


def test_popular_list_is_optional(tmp_path: Path) -> None:
    assert load_popular(tmp_path / "missing.txt") == frozenset()
    listed = tmp_path / "popular.txt"
    listed.write_text("google.de\nExample.ORG\n")
    assert load_popular(listed) == frozenset({"google.de", "example.org"})


# --- the checks --------------------------------------------------------------


async def run(url: str) -> dict[str, Any]:
    checks: list[Check[ParsedUrl]] = [LookalikeCheck(DETECTOR), IdnCheck()]
    findings = await run_checks(checks, parse_url(url), make_context())
    return {f.id: f for f in findings}


async def test_homograph_finding_shows_both_domains() -> None:
    findings = await run("https://p\N{CYRILLIC SMALL LETTER A}ypal.com/signin")
    assert set(findings) == {
        "url.lookalike.homograph",
        "url.idn.punycode",
        "url.idn.mixed_script",
    }
    homograph = findings["url.lookalike.homograph"]
    assert homograph.severity is Severity.CRITICAL
    assert "PayPal" in homograph.title and "paypal.com" in homograph.explanation
    side_by_side = homograph.evidence[0]
    assert isinstance(side_by_side, LookalikeEvidence)
    assert side_by_side.seen_ascii == "xn--pypal-4ve.com"
    assert side_by_side.genuine == "paypal.com"
    assert side_by_side.differences[0].position == 1


@pytest.mark.parametrize(
    ("url", "finding", "severity"),
    [
        ("https://paypa1.com/", "url.lookalike.character_swap", Severity.HIGH),
        ("https://paypla.com/", "url.lookalike.typo", Severity.HIGH),
        ("https://paypal.co/", "url.lookalike.tld_swap", Severity.HIGH),
        ("https://paypal-secure-login.com/", "url.lookalike.combo", Severity.MEDIUM),
    ],
)
async def test_lookalike_severities(url: str, finding: str, severity: Severity) -> None:
    findings = await run(url)
    assert set(findings) == {finding}
    assert findings[finding].severity is severity


@pytest.mark.parametrize(
    "url",
    [
        "https://accounts.google.com/",
        "https://login.microsoftonline.com/",
        "https://www.amazon.co.uk/",
        "https://www.paypal.com/",
        "https://example.com/",
    ],
)
async def test_legitimate_sites_have_no_domain_findings(url: str) -> None:
    assert await run(url) == {}


async def test_real_international_name_is_only_informational() -> None:
    findings = await run("http://m\N{LATIN SMALL LETTER U WITH DIAERESIS}nchen.de/")
    assert set(findings) == {"url.idn.punycode"}
    assert findings["url.idn.punycode"].severity is Severity.INFO
