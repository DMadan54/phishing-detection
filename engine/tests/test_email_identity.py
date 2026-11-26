"""Sender identity, header consistency and date checks."""

from datetime import UTC, datetime

import pytest

from phishlens.brands import load_brands
from phishlens.email.dates import DateCheck
from phishlens.email.from_check import FromCheck
from phishlens.email.headers import HeaderConsistencyCheck
from phishlens.email.parse import ParsedEmail, parse_email
from phishlens.findings import Check, Severity
from phishlens.lookalike import LookalikeMatch
from tests.email_checks import findings_for, ids_for
from tests.fakes import FixedClock, make_context


class FakeLookalikes:
    """Stands in for the real detector (URL and domain milestone)."""

    def check(self, domain: str) -> LookalikeMatch | None:
        if domain != "paypa1.test":
            return None
        paypal = next(b for b in load_brands() if b.name == "PayPal")
        return LookalikeMatch(paypal, domain, 'uses "1" in place of "l" in paypal')


IDENTITY_CHECKS: list[Check[ParsedEmail]] = [
    FromCheck(FakeLookalikes()),
    HeaderConsistencyCheck(),
    DateCheck(),
]

EXPECTED: dict[str, set[str]] = {
    "plain_safe": set(),
    "legit_dkim_signed": set(),
    "legit_subdomain_relaxed": set(),
    "esp_signed": set(),
    "brand_spoof_dmarc_fail": {"email.headers.return_path_mismatch"},
    "forged_auth_results": {"email.headers.return_path_mismatch"},
    "display_name_spoof": {
        "email.from.display_name_address",
        "email.from.display_name_brand",
        "email.headers.message_id_unrelated",
    },
    "lookalike_sender": {"email.from.display_name_brand", "email.from.lookalike"},
    "reply_to_hijack": {"email.headers.reply_to_mismatch"},
    "mailing_list_forwarded": {
        "email.headers.reply_to_mismatch",
        "email.headers.return_path_mismatch",
    },
    "malformed": {"email.from.invalid", "email.headers.message_id_missing", "email.date.invalid"},
    "date_future": {"email.date.future"},
    "date_stale": {"email.headers.message_id_missing", "email.date.stale"},
}

ALL_IDS = {
    "email.from.invalid",
    "email.from.display_name_address",
    "email.from.display_name_brand",
    "email.from.lookalike",
    "email.headers.reply_to_mismatch",
    "email.headers.return_path_mismatch",
    "email.headers.message_id_missing",
    "email.headers.message_id_unrelated",
    "email.date.future",
    "email.date.stale",
    "email.date.invalid",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
async def test_fixture_findings(name: str) -> None:
    assert await ids_for(name, IDENTITY_CHECKS) == EXPECTED[name]


def test_every_id_has_a_positive_and_a_negative() -> None:
    for finding_id in ALL_IDS:
        assert any(finding_id in ids for ids in EXPECTED.values()), finding_id
        assert any(finding_id not in ids for ids in EXPECTED.values()), finding_id


async def test_real_detector_default_finds_no_lookalikes_yet() -> None:
    assert await ids_for("lookalike_sender", [FromCheck()]) == {"email.from.display_name_brand"}


async def test_mailing_list_reply_to_is_lowered() -> None:
    findings = await findings_for("mailing_list_forwarded", [HeaderConsistencyCheck()])
    reply_to = next(f for f in findings if f.id.endswith("reply_to_mismatch"))
    assert reply_to.severity is Severity.LOW


def msg(*headers: str) -> ParsedEmail:
    return parse_email(("\r\n".join(headers) + "\r\n\r\nbody\r\n").encode())


@pytest.mark.parametrize(
    ("from_header", "expected"),
    [
        # The display name repeats the real address: honest.
        ("From: Jane <jane@company.example>", set()),
        ("From: jane@company.example <jane@company.example>", set()),
        # Same organisation, different mailbox: not a spoof.
        ("From: help@company.example <noreply@mail.company.example>", set()),
        # Brand named, brand's own subdomain: fine.
        ("From: PayPal <service@mail.paypal.com>", set()),
        # Whole words only.
        ("From: Pineapple Farm <news@farm.example>", set()),
        ("From: Apple Support <support@farm.example>", {"email.from.display_name_brand"}),
        (
            'From: "billing@paypal.com via Mailer" <x@evil.test>',
            {"email.from.display_name_address", "email.from.display_name_brand"},
        ),
        # Unquoted, the same header is ambiguous: Python's parser reads it as
        # billing@paypal.com, other software as x@evil.test.
        ("From: billing@paypal.com via Mailer <x@evil.test>", {"email.from.invalid"}),
    ],
)
async def test_display_name_edge_cases(from_header: str, expected: set[str]) -> None:
    ids = await ids_for(msg(from_header, "Message-ID: <1@company.example>"), [FromCheck()])
    assert ids == expected


async def test_future_date_without_received_uses_the_clock() -> None:
    message = msg("From: a@company.example", "Date: Fri, 01 Jan 2027 00:00:00 +0000")
    ctx = make_context(clock=FixedClock(datetime(2026, 6, 1, tzinfo=UTC)))
    assert {f.id for f in await DateCheck().run(message, ctx)} == {"email.date.future"}


async def test_old_email_without_received_is_not_stale() -> None:
    message = msg("From: a@company.example", "Date: Thu, 01 Jan 2015 00:00:00 +0000")
    ctx = make_context(clock=FixedClock(datetime(2026, 6, 1, tzinfo=UTC)))
    assert await DateCheck().run(message, ctx) == []


async def test_missing_date_header_is_invalid() -> None:
    findings = await DateCheck().run(msg("From: a@company.example"), make_context())
    assert [(f.id, f.title) for f in findings] == [("email.date.invalid", "No date")]
