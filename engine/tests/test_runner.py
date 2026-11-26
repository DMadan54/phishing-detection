import logging

import pytest

from phishlens.findings import Check, Severity
from phishlens.runner import run_checks
from phishlens.subjects import RawEmail
from tests.checks import CrashingCheck, HangingCheck, StaticCheck
from tests.fakes import make_context

SECRET = b"From: alice@example.com\r\nSubject: private\r\n\r\nhello"


async def test_findings_come_back_in_check_order() -> None:
    checks = [StaticCheck("email.b"), StaticCheck("email.a")]
    findings = await run_checks(checks, RawEmail(SECRET), make_context())
    assert [f.id for f in findings] == ["email.b.seen", "email.a.seen"]


async def test_no_checks_means_no_findings() -> None:
    assert await run_checks([], RawEmail(SECRET), make_context()) == []


async def test_crash_becomes_check_error_without_leaking_input(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    checks: list[Check[RawEmail]] = [CrashingCheck("email.broken"), StaticCheck("email.fine")]
    findings = await run_checks(checks, RawEmail(SECRET), make_context())

    assert [f.id for f in findings] == ["email.broken.check_error", "email.fine.seen"]
    error = findings[0]
    assert error.severity is Severity.INFO
    assert "alice" not in error.explanation
    assert "alice" not in caplog.text
    assert "ValueError" in caplog.text


async def test_hanging_check_times_out() -> None:
    findings = await run_checks(
        [HangingCheck("email.slow")], RawEmail(SECRET), make_context(), timeout=0.05
    )
    assert [f.id for f in findings] == ["email.slow.check_error"]
