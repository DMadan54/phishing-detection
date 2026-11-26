"""SPF, DKIM, DMARC, Authentication-Results and forwarding checks."""

import asyncio

import pytest

from phishlens.email.auth import evaluate_spf, find_dmarc_policy, parse_dmarc
from phishlens.email.auth_dkim import DkimCheck
from phishlens.email.auth_dmarc import DmarcCheck
from phishlens.email.auth_results import AuthResultsCheck
from phishlens.email.auth_spf import SpfCheck
from phishlens.email.config import EmailConfig
from phishlens.email.forwarding import ForwardingCheck
from phishlens.email.parse import ParsedEmail
from phishlens.findings import Check, Severity
from tests.email_checks import findings_for, ids_for
from tests.email_world import fixture, world_dns
from tests.fakes import FakeDns, make_context

AUTH_CHECKS: list[Check[ParsedEmail]] = [
    SpfCheck(),
    DkimCheck(),
    DmarcCheck(),
    AuthResultsCheck(),
    ForwardingCheck(),
]

# The exact authentication findings each fixture must produce. Being exact
# makes every row both a positive test (these ids appear) and a negative
# test (no other authentication id does).
EXPECTED: dict[str, set[str]] = {
    "plain_safe": {"email.dkim.missing", "email.dmarc.pass"},
    "legit_dkim_signed": {"email.dmarc.pass", "email.auth_results.untrusted"},
    "legit_subdomain_relaxed": {"email.dmarc.pass"},
    "esp_signed": {"email.dkim.other_domain", "email.dmarc.pass"},
    "tampered_signed": {"email.dkim.invalid", "email.dmarc.pass"},
    "brand_spoof_dmarc_fail": {"email.dkim.other_domain", "email.dmarc.not_aligned"},
    "lookalike_sender": {"email.dmarc.pass"},
    "display_name_spoof": {"email.spf.none", "email.dkim.missing", "email.dmarc.no_policy"},
    "reply_to_hijack": {"email.spf.fail", "email.dkim.missing", "email.dmarc.fail"},
    "forged_auth_results": {
        "email.dkim.missing",
        "email.dmarc.not_aligned",
        "email.auth_results.untrusted",
        "email.auth_results.contradicted",
    },
    "mailing_list_forwarded": {
        "email.dkim.invalid",
        "email.dkim.other_domain",
        "email.dmarc.not_aligned",
        "email.auth_results.untrusted",
        "email.forwarding.mailing_list",
    },
    "malformed": {"email.spf.no_sending_ip", "email.dkim.missing"},
    "spf_softfail": {"email.spf.softfail", "email.dkim.missing", "email.dmarc.fail"},
    "spf_permerror": {"email.spf.error", "email.dkim.missing", "email.dmarc.fail"},
}

ALL_AUTH_IDS = {
    "email.spf.fail",
    "email.spf.softfail",
    "email.spf.none",
    "email.spf.error",
    "email.spf.no_sending_ip",
    "email.dkim.missing",
    "email.dkim.invalid",
    "email.dkim.other_domain",
    "email.dmarc.not_aligned",
    "email.dmarc.fail",
    "email.dmarc.no_policy",
    "email.dmarc.pass",
    "email.auth_results.untrusted",
    "email.auth_results.contradicted",
    "email.forwarding.mailing_list",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
async def test_fixture_findings(name: str) -> None:
    assert await ids_for(name, AUTH_CHECKS) == EXPECTED[name]


def test_every_id_has_a_positive_and_a_negative() -> None:
    for finding_id in ALL_AUTH_IDS:
        assert any(finding_id in ids for ids in EXPECTED.values()), f"no positive for {finding_id}"
        assert any(finding_id not in ids for ids in EXPECTED.values()), (
            f"no negative for {finding_id}"
        )


# --- the key case: SPF passes, but for someone else --------------------------


async def test_brand_spoof_names_both_domains() -> None:
    (finding,) = [
        f for f in await findings_for("brand_spoof_dmarc_fail", AUTH_CHECKS) if "dmarc" in f.id
    ]
    assert finding.severity is Severity.HIGH
    assert "evil.test" in finding.explanation and "paypal.com" in finding.explanation
    assert "reject" in finding.explanation
    assert [e.name for e in finding.evidence][:2] == ["From", "Return-Path"]  # type: ignore[union-attr]


async def test_policy_none_is_less_severe() -> None:
    dns = world_dns()
    dns.records[("_dmarc.paypal.com", "TXT")] = ["v=DMARC1; p=none"]
    (finding,) = [
        f
        for f in await findings_for("brand_spoof_dmarc_fail", [DmarcCheck()], dns)
        if "dmarc" in f.id
    ]
    assert finding.severity is Severity.MEDIUM


async def test_strict_alignment_rejects_subdomains() -> None:
    dns = world_dns()
    dns.records[("_dmarc.shop.example", "TXT")] = ["v=DMARC1; p=reject; adkim=s; aspf=s"]
    ids = await ids_for("legit_subdomain_relaxed", [DmarcCheck()], dns)
    assert ids == {"email.dmarc.not_aligned"}


# --- mailing lists -----------------------------------------------------------


async def test_mailing_list_lowers_severity_one_step() -> None:
    findings = {f.id: f for f in await findings_for("mailing_list_forwarded", AUTH_CHECKS)}
    assert findings["email.dkim.invalid"].severity is Severity.LOW
    assert findings["email.dmarc.not_aligned"].severity is Severity.MEDIUM


async def test_list_id_without_valid_arc_changes_nothing() -> None:
    raw = fixture("mailing_list_forwarded").raw.replace(b"ARC-Seal:", b"X-Old-Seal:")
    from phishlens.email.parse import parse_email

    findings = {f.id: f for f in await findings_for(parse_email(raw), AUTH_CHECKS)}
    assert "email.forwarding.mailing_list" not in findings
    assert findings["email.dmarc.not_aligned"].severity is Severity.HIGH


# --- Authentication-Results trust --------------------------------------------


async def test_trusted_authserv_is_not_reported() -> None:
    config = EmailConfig(trusted_authserv_ids=frozenset({"mx.recipient.example"}))
    ids = await ids_for("legit_dkim_signed", [AuthResultsCheck(config)])
    assert ids == set()


async def test_forged_header_is_contradicted_even_if_it_names_a_big_provider() -> None:
    findings = await findings_for("forged_auth_results", [AuthResultsCheck()])
    contradicted = next(f for f in findings if f.id.endswith("contradicted"))
    assert "mx.google.com" in contradicted.explanation


async def test_trusted_dmarc_pass_covers_rotated_keys() -> None:
    dns = world_dns()
    del dns.records[("s1._domainkey.shop.example", "TXT")]
    del dns.records[("mail.shop.example", "TXT")]
    config = EmailConfig(trusted_authserv_ids=frozenset({"mx.recipient.example"}))

    untrusted = await findings_for("legit_dkim_signed", [DmarcCheck()], dns)
    assert {f.id for f in untrusted} == {"email.dmarc.fail"}

    (trusted,) = await findings_for("legit_dkim_signed", [DmarcCheck(config)], dns)
    assert trusted.id == "email.dmarc.pass"
    assert "on delivery" in trusted.explanation


# --- SPF details -------------------------------------------------------------


async def test_trusted_receivers_that_do_not_match_give_no_hop() -> None:
    config = EmailConfig(trusted_receivers=frozenset({"other-provider.example"}))
    assert await ids_for("plain_safe", [SpfCheck(config)]) == {"email.spf.no_sending_ip"}


async def test_spf_dns_failure_is_a_temperror() -> None:
    dns = world_dns()
    dns.failing.add(("company.example", "TXT"))
    findings = await findings_for("plain_safe", [SpfCheck()], dns)
    assert [f.id for f in findings] == ["email.spf.error"]
    assert "DNS lookup failed" in findings[0].explanation


async def test_concurrent_spf_checks_use_their_own_dns() -> None:
    allow = world_dns()
    deny = world_dns()
    deny.records[("company.example", "TXT")] = ["v=spf1 -all"]
    msg = fixture("plain_safe")

    async def result(dns: FakeDns) -> str | None:
        return (await evaluate_spf(msg, make_context(dns=dns), EmailConfig())).result

    results = await asyncio.gather(*(result(d) for d in [allow, deny] * 5))
    assert results == ["pass", "fail"] * 5


async def test_dmarc_dns_failure_becomes_check_error() -> None:
    dns = world_dns()
    dns.failing.add(("_dmarc.paypal.com", "TXT"))
    ids = await ids_for("brand_spoof_dmarc_fail", [DmarcCheck()], dns)
    assert ids == {"email.dmarc.check_error"}


# --- DMARC record parsing ----------------------------------------------------


def test_parse_dmarc_defaults() -> None:
    policy = parse_dmarc("v=DMARC1; p=reject", "x.example", for_subdomain=False)
    assert policy is not None
    assert (policy.policy, policy.adkim, policy.aspf, policy.pct) == ("reject", "r", "r", 100)


def test_parse_dmarc_subdomain_policy() -> None:
    record = "v=DMARC1; p=reject; sp=none; adkim=s"
    policy = parse_dmarc(record, "x.example", for_subdomain=True)
    assert policy is not None and policy.policy == "none" and policy.adkim == "s"


@pytest.mark.parametrize("record", ["v=spf1 -all", "p=reject; v=DMARC1", "v=DMARC2; p=reject"])
def test_parse_dmarc_rejects_non_records(record: str) -> None:
    assert parse_dmarc(record, "x.example", for_subdomain=False) is None


def test_invalid_policy_means_none() -> None:
    policy = parse_dmarc("v=DMARC1; p=bogus", "x.example", for_subdomain=False)
    assert policy is not None and policy.policy == "none"


async def test_policy_falls_back_to_the_organisational_domain() -> None:
    dns = FakeDns().add("_dmarc.shop.example", "TXT", "v=DMARC1; p=reject; sp=quarantine")
    policy = await find_dmarc_policy("mail.shop.example", dns)
    assert (
        policy is not None and policy.found_at == "shop.example" and policy.policy == "quarantine"
    )


async def test_two_records_mean_no_policy() -> None:
    dns = FakeDns().add("_dmarc.x.example", "TXT", "v=DMARC1; p=reject", "v=DMARC1; p=none")
    assert await find_dmarc_policy("x.example", dns) is None
