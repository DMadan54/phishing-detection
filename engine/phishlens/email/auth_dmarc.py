"""DMARC: did the domain in From authorise this message?

This is the check that matters most for spoofing. SPF and DKIM each say
"domain X handled this message". DMARC asks whether X is the domain the
reader sees in From ("alignment"):

- relaxed alignment: same organisational domain (mail.paypal.com and
  paypal.com both belong to paypal.com);
- strict alignment: exactly the same name.

The From domain publishes which mode it wants (adkim=, aspf=) and what to do
with mail that fails (p=none, quarantine or reject).

The classic spoof passes SPF perfectly, for the attacker's own domain, while
From says paypal.com. That's email.dmarc.not_aligned.
"""

from dataclasses import dataclass, field

from phishlens.email import evidence
from phishlens.email.auth import DmarcEvaluation, evaluate_dmarc, is_mailing_list, lower
from phishlens.email.auth_results import parse_auth_results, trusted_dmarc_pass
from phishlens.email.config import EmailConfig
from phishlens.email.parse import ParsedEmail
from phishlens.findings import CheckContext, Finding, HeaderEvidence, Severity

_ACTION = {
    "reject": "reject mail like this",
    "quarantine": "treat mail like this as spam",
    "none": "only monitor mail like this",
}


@dataclass(frozen=True)
class DmarcCheck:
    config: EmailConfig = field(default_factory=EmailConfig)
    name: str = "email.dmarc"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        sender = msg.from_address
        if sender is None or sender.domain is None:
            return []  # email.from.invalid reports this
        result = await evaluate_dmarc(msg, ctx, self.config, sender.domain)
        proof = self._evidence(msg, result)
        domain = sender.domain

        def finding(what: str, severity: Severity, title: str, explanation: str) -> Finding:
            return Finding(
                id=f"{self.name}.{what}",
                check=self.name,
                severity=severity,
                title=title,
                explanation=explanation,
                evidence=proof,
            )

        if result.passed:
            how = "SPF" if result.spf_aligned else f"A DKIM signature from {result.dkim_aligned[0]}"
            return [
                finding(
                    "pass",
                    Severity.INFO,
                    f"{domain} authorised this message",
                    f"{how} confirms that {domain} sent this message (DMARC passed). That "
                    "proves where it came from, not that the sender is trustworthy.",
                )
            ]

        if trusted_dmarc_pass(parse_auth_results(msg), self.config, domain):
            return [
                finding(
                    "pass",
                    Severity.INFO,
                    f"{domain} authorised this message when it arrived",
                    f"Your mail provider recorded DMARC passing for {domain} on delivery. "
                    "Checking again now fails, most likely because the sender's keys or "
                    "records have changed since, so the provider's result is used.",
                )
            ]

        elsewhere = ", ".join(result.passed_elsewhere)
        if result.policy is None:
            extra = (
                f" It did pass checks for {elsewhere}, but that says nothing about {domain}."
                if elsewhere
                else ""
            )
            return [
                finding(
                    "no_policy",
                    Severity.LOW,
                    f"{domain} doesn't protect its address with DMARC",
                    f"{domain} publishes no DMARC policy, so nothing ties the From address to "
                    "the servers that sent the message: anyone can put this address in From."
                    + extra,
                )
            ]

        policy = result.policy
        severity = Severity.MEDIUM if policy.policy == "none" else Severity.HIGH
        forwarded = await is_mailing_list(msg, ctx)
        if forwarded:
            severity = lower(severity)
        tail = f" {domain}'s own policy says to {_ACTION[policy.policy]}."
        if forwarded:
            tail += (
                " It came through a mailing list, which often breaks SPF and DKIM for the "
                "original sender."
            )

        if result.passed_elsewhere:
            what = "SPF or DKIM" if len(result.passed_elsewhere) > 1 else self._method(result)
            return [
                finding(
                    "not_aligned",
                    severity,
                    f"Passes checks for {elsewhere}, but claims to be {domain}",
                    f"The message passed {what} for {elsewhere}, but it claims to be from "
                    f"{domain}. Passing checks for a different domain proves nothing about "
                    f"{domain}." + tail,
                )
            ]

        spf = result.spf.result or "not checkable"
        return [
            finding(
                "fail",
                severity,
                f"Nothing confirms that {domain} sent this",
                f"SPF gives '{spf}' and there's no valid DKIM signature from {domain}, so "
                f"nothing shows that {domain} sent this message." + tail,
            )
        ]

    @staticmethod
    def _method(result: DmarcEvaluation) -> str:
        first = result.passed_elsewhere[0]
        return "SPF" if first == result.spf.domain and result.spf.result == "pass" else "DKIM"

    @staticmethod
    def _evidence(msg: ParsedEmail, result: DmarcEvaluation) -> tuple[HeaderEvidence, ...]:
        found = [*evidence.header(msg, "From"), *evidence.header(msg, "Return-Path")]
        found += [evidence.from_field(f) for f in msg.headers_named("DKIM-Signature")]
        return tuple(found)
