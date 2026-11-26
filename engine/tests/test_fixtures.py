"""The fixtures themselves: reproducible, parseable, and signed correctly."""

import dkim
import pytest

from tests.email_world import FIXTURES, fixture, fixture_names, raw_fixture, world_dns
from tests.fixtures.email.build_fixtures import FIXTURES as BUILDERS
from tests.fixtures.email.build_fixtures import build_all


def test_files_on_disk_match_the_builder() -> None:
    built = build_all()
    assert sorted(built) == fixture_names()
    for name, raw in built.items():
        assert raw_fixture(name) == raw, f"{name}.eml is stale: rerun build_fixtures"


def test_there_are_enough_fixtures() -> None:
    assert len(BUILDERS) >= 12


@pytest.mark.parametrize("name", fixture_names())
def test_every_fixture_parses(name: str) -> None:
    parsed = fixture(name)
    assert parsed.raw == raw_fixture(name)


def _dns_for_dkimpy(name: bytes, timeout: int = 5) -> bytes | None:
    records = world_dns().records.get((name.decode().rstrip("."), "TXT"))
    return records[0].encode() if records else None


@pytest.mark.parametrize(
    ("name", "valid"),
    [("legit_dkim_signed", True), ("esp_signed", True), ("tampered_signed", False)],
)
def test_signatures_verify_as_intended(name: str, valid: bool) -> None:
    assert dkim.verify(raw_fixture(name), dnsfunc=_dns_for_dkimpy) is valid


def test_mailing_list_arc_chain_is_valid() -> None:
    cv, _, _ = dkim.arc_verify(raw_fixture("mailing_list_forwarded"), dnsfunc=_dns_for_dkimpy)
    assert cv == b"pass"


def test_fixtures_use_reserved_names_only() -> None:
    allowed_real = (b"paypal.com", b"google.com", b"bit.ly", b"rua.agari.com")
    for path in FIXTURES.glob("*.eml"):
        raw = path.read_bytes()
        for token in raw.replace(b">", b" ").replace(b"<", b" ").split():
            if b"@" in token and b"." in token.rsplit(b"@", 1)[-1]:
                domain = token.rsplit(b"@", 1)[-1].strip(b'",;')
                assert domain.endswith((b".example", b".test", *allowed_real)), (path.name, domain)
