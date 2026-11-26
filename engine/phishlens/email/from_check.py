"""Who the message says it's from, and whether that holds together.

Most people only read the display name ("PayPal Service"), not the address
after it. So a display name that names a brand, or contains an email address
of its own, while the real address is somewhere else, is a cheap and very
common trick. None of this needs DNS: it's about what the reader is shown.
"""

import re
from dataclasses import dataclass, field

from phishlens.brands import brands_named_in
from phishlens.domains import domain_of_address, same_owner
from phishlens.email import evidence
from phishlens.email.parse import Address, ParsedEmail
from phishlens.findings import CheckContext, Finding, Severity
from phishlens.lookalike import LookalikeDetector, NoLookalikes

_ADDRESS_IN_TEXT = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
_BRACKETED = re.compile(r"<\s*([^<>\s]+@[^<>\s]+)\s*>")


@dataclass(frozen=True)
class FromCheck:
    lookalikes: LookalikeDetector = field(default_factory=NoLookalikes)
    name: str = "email.from"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        problem = self._invalid(msg)
        if problem:
            return [
                self._finding(
                    "invalid", Severity.MEDIUM, "The From address is broken", problem, msg
                )
            ]
        sender = msg.from_address
        if sender is None or sender.domain is None:
            return []
        return [
            *self._display_name_address(msg, sender),
            *self._display_name_brand(msg, sender),
            *self._lookalike(msg, sender),
        ]

    def _invalid(self, msg: ParsedEmail) -> str | None:
        if msg.from_header_count == 0:
            return "The message has no From header at all, so it doesn't say who sent it."
        if msg.from_header_count > 1:
            return (
                "The message has more than one From header. Different programs show different "
                "ones, which lets a sender show you one address while filters check another."
            )
        if len(msg.from_addresses) != 1:
            return "The From header doesn't contain exactly one address."
        if msg.from_addresses[0].domain is None:
            return "The From address doesn't have a valid domain."
        # An unquoted address in the display name makes the header ambiguous:
        # "billing@paypal.com via X <x@evil.test>" is read by some software as
        # billing@paypal.com and by others as x@evil.test. Two readings at the
        # same organisation are harmless, so only different owners count.
        header = msg.header("From")
        bracketed = _BRACKETED.findall(header.raw) if header else []
        parsed = msg.from_addresses[0].addr_spec
        other = domain_of_address(bracketed[-1]) if bracketed else None
        if other and not same_owner(other, msg.from_addresses[0].domain):
            return (
                f"The From header can be read two ways: as {parsed} or as {bracketed[-1]}. "
                "Different mail programs pick different ones, so you may be shown one sender "
                "while filters check the other."
            )
        return None

    def _display_name_address(self, msg: ParsedEmail, sender: Address) -> list[Finding]:
        findings = []
        for shown in _ADDRESS_IN_TEXT.findall(sender.display_name):
            shown_domain = domain_of_address(shown)
            if shown.lower() == sender.addr_spec.lower():
                continue
            if shown_domain and same_owner(shown_domain, sender.domain or ""):
                continue
            findings.append(
                self._finding(
                    "display_name_address",
                    Severity.HIGH,
                    "The name shows a different email address",
                    f"The sender's name is shown as '{shown}', but the message really comes "
                    f"from {sender.addr_spec}. Many mail apps show only the name, so you'd "
                    "see an address that isn't the sender.",
                    msg,
                )
            )
        return findings[:1]

    def _display_name_brand(self, msg: ParsedEmail, sender: Address) -> list[Finding]:
        for brand, _where in brands_named_in(sender.display_name):
            if brand.owns(sender.domain or ""):
                continue
            return [
                self._finding(
                    "display_name_brand",
                    Severity.MEDIUM,
                    f"Uses the name {brand.name}, but isn't from {brand.name}",
                    f"The sender calls itself '{sender.display_name}', which names "
                    f"{brand.name}, but the address is at {sender.domain}, which isn't one "
                    f"of {brand.name}'s domains.",
                    msg,
                )
            ]
        return []

    def _lookalike(self, msg: ParsedEmail, sender: Address) -> list[Finding]:
        match = self.lookalikes.check(sender.domain or "")
        if match is None:
            return []
        return [
            self._finding(
                "lookalike",
                Severity.HIGH,
                f"The sender's domain imitates {match.brand.name}",
                f"The address is at {match.domain}, which looks like a {match.brand.name} "
                f"domain but isn't one: it {match.reason}.",
                msg,
            )
        ]

    def _finding(
        self, what: str, severity: Severity, title: str, explanation: str, msg: ParsedEmail
    ) -> Finding:
        proof = tuple(evidence.from_field(f) for f in msg.headers_named("From"))
        return Finding(
            id=f"{self.name}.{what}",
            check=self.name,
            severity=severity,
            title=title,
            explanation=explanation,
            evidence=proof,
        )
