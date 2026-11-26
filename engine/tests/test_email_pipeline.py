"""Every registered email check, together, on every fixture and on broken input."""

import random

import httpx
import pytest

from phishlens.api import create_app
from phishlens.email.config import EmailConfig
from phishlens.email.parse import parse_email
from phishlens.findings import Severity
from phishlens.registry import default_registry
from tests.email_checks import findings_for
from tests.email_world import fixture_names, raw_fixture, world_dns
from tests.fakes import make_context

CHECKS = default_registry(EmailConfig()).email_checks
VARIANTS_PER_FIXTURE = 12


def mangle(raw: bytes, rng: random.Random) -> bytes:
    """One random kind of damage: the sort of thing a hostile or broken
    message might contain."""
    data = bytearray(raw)
    match rng.randrange(8):
        case 0:  # cut off anywhere
            return bytes(data[: rng.randrange(len(data) + 1)])
        case 1:  # random bytes changed
            for _ in range(rng.randrange(1, 20)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            return bytes(data)
        case 2:  # NUL bytes sprinkled in
            for _ in range(rng.randrange(1, 10)):
                data.insert(rng.randrange(len(data)), 0)
            return bytes(data)
        case 3:  # bare LF line endings
            return raw.replace(b"\r\n", b"\n")
        case 4:  # header block repeated
            head, _, body = raw.partition(b"\r\n\r\n")
            return head + b"\r\n" + head + b"\r\n\r\n" + body
        case 5:  # MIME boundaries destroyed
            return raw.replace(b"--", b"-")
        case 6:  # a junk header line in the middle
            cut = raw.find(b"\r\n", rng.randrange(max(1, len(raw) // 2))) + 2
            return (
                raw[:cut] + bytes(rng.randrange(33, 127) for _ in range(80)) + b"\r\n" + raw[cut:]
            )
        case _:  # halves swapped
            middle = len(raw) // 2
            return raw[middle:] + raw[:middle]


@pytest.mark.parametrize("name", fixture_names())
async def test_no_check_ever_crashes(name: str) -> None:
    rng = random.Random(f"phishlens-{name}")  # fixed seed: failures are reproducible
    inputs = [raw_fixture(name)] + [
        mangle(raw_fixture(name), rng) for _ in range(VARIANTS_PER_FIXTURE)
    ]
    for raw in inputs:
        findings = await findings_for(parse_email(raw), CHECKS)
        crashed = [f.id for f in findings if f.id.endswith(".check_error")]
        assert not crashed, (name, crashed)


@pytest.mark.parametrize("name", ["plain_safe", "legit_dkim_signed", "legit_subdomain_relaxed"])
async def test_legitimate_mail_stays_quiet(name: str) -> None:
    for finding in await findings_for(name, CHECKS):
        assert finding.severity in (Severity.INFO, Severity.LOW), finding.id


async def test_api_analyses_a_real_fixture_end_to_end() -> None:
    app = create_app(
        registry=default_registry(EmailConfig()), context=make_context(dns=world_dns())
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyse/email",
            content=raw_fixture("brand_spoof_dmarc_fail"),
            headers={"Content-Type": "message/rfc822"},
        )
    assert response.status_code == 200
    report = response.json()
    ids = {f["id"] for f in report["findings"]}
    assert {"email.dmarc.not_aligned", "email.language.urgency"} <= ids
    assert "email.spf" in report["checks_run"]
    from_evidence = next(
        e for f in report["findings"] if f["id"] == "email.dmarc.not_aligned" for e in f["evidence"]
    )
    raw = raw_fixture("brand_spoof_dmarc_fail")
    span = from_evidence["span"]
    assert raw[span["start"] : span["end"]].startswith(b"From:")
