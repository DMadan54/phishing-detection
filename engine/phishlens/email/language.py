"""Pressure and credential-request language.

Phishing works by hurrying people ("your account will be closed within 24
hours") and then asking for exactly what it wants ("confirm your password").
A short, readable list of patterns finds the phrases and quotes them.

These findings are always LOW and are supporting evidence only. Plenty of
genuine mail is urgent or asks you to sign in; the wording just makes other
findings more convincing.
"""

import re
from dataclasses import dataclass

from phishlens.email.parse import ParsedEmail
from phishlens.findings import BodyEvidence, CheckContext, Finding, Severity

MAX_QUOTES = 3

URGENCY = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\baccount (?:has been |will be |is |was )?"
        r"(?:suspended|locked|disabled|closed|restricted|deactivated|on hold)\b",
        r"\bwithin \d+\s*(?:hours?|hrs?|days?)\b",
        r"\b(?:immediate|urgent) (?:action|attention|response)\b",
        r"\bpayment (?:has )?"
        r"(?:failed|was declined|declined|was unsuccessful|could not be processed)\b",
        r"\bfinal (?:notice|warning|reminder)\b",
        r"\bunusual (?:activity|sign-?in)\b",
        r"\bwill be (?:closed|terminated|deleted|suspended)\b",
        r"\burgent(?:ly)?\b",
    )
)

CREDENTIALS = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:verify|confirm|update|validate) (?:your )?(?:account|identity|password|login|"
        r"details|information|payment (?:details|information)|billing (?:details|information))\b",
        r"\b(?:enter|provide|re-?enter|send) (?:your )?(?:password|pin|credentials|"
        r"card (?:number|details)|security code|one[- ]time (?:code|password))\b",
        r"\b(?:log ?in|sign ?in) (?:to|and) (?:verify|confirm|restore|unlock)\b",
        r"\brestore (?:your )?(?:account|access)\b",
    )
)


def matches(patterns: tuple[re.Pattern[str], ...], text: str) -> list[str]:
    found: dict[str, None] = {}
    for pattern in patterns:
        for match in pattern.finditer(text):
            found.setdefault(match.group(0), None)
    return list(found)[:MAX_QUOTES]


@dataclass(frozen=True)
class LanguageCheck:
    name: str = "email.language"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        text = " ".join(msg.readable_text().split())
        findings = []
        urgent = matches(URGENCY, text)
        if urgent:
            findings.append(
                self._finding(
                    "urgency",
                    "Pressure to act quickly",
                    urgent,
                    "Phishing hurries people so they act before thinking.",
                )
            )
        asks = matches(CREDENTIALS, text)
        if asks:
            findings.append(
                self._finding(
                    "credential_request",
                    "Asks you to confirm account details",
                    asks,
                    "Real organisations rarely ask you to confirm passwords or account "
                    "details from an email.",
                )
            )
        return findings

    def _finding(self, what: str, title: str, quotes: list[str], why: str) -> Finding:
        quoted = ", ".join(f"'{q}'" for q in quotes)
        return Finding(
            id=f"{self.name}.{what}",
            check=self.name,
            severity=Severity.LOW,
            title=title,
            explanation=(
                f"The message says {quoted}. {why} This is supporting evidence only: plenty of "
                "genuine messages use words like these."
            ),
            evidence=tuple(BodyEvidence(excerpt=q) for q in quotes),
        )
