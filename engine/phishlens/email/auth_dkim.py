"""DKIM: which domains signed this message, and are the signatures intact?

What it proves: the domain in d= handled the message, and the signed
headers and body haven't changed since. What it doesn't prove: that d= is
the domain in From. Anyone can sign with their own domain.
"""

from dataclasses import dataclass

from phishlens.domains import same_owner
from phishlens.email import evidence
from phishlens.email.auth import is_mailing_list, lower, verify_dkim
from phishlens.email.parse import ParsedEmail
from phishlens.findings import CheckContext, Finding, HeaderEvidence, Severity


@dataclass(frozen=True)
class DkimCheck:
    name: str = "email.dkim"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        signatures = await verify_dkim(msg, ctx)
        if not signatures:
            return [
                Finding(
                    id=f"{self.name}.missing",
                    check=self.name,
                    severity=Severity.LOW,
                    title="Not signed with DKIM",
                    explanation=(
                        "The message has no DKIM signature, so there's no cryptographic proof of "
                        "which domain sent it or that it wasn't changed on the way. Plenty of "
                        "ordinary mail is unsigned, so this matters most alongside other signs."
                    ),
                    evidence=tuple(evidence.header(msg, "From")),
                )
            ]

        fields = msg.headers_named("DKIM-Signature")
        forwarded = await is_mailing_list(msg, ctx)
        sender = msg.from_address
        from_domain = sender.domain if sender else None
        findings: list[Finding] = []

        for sig, field in zip(signatures, fields, strict=False):
            proof: tuple[HeaderEvidence, ...] = (evidence.from_field(field),)
            signer = sig.domain or "an unnamed domain"
            if sig.status in ("fail", "permerror"):
                severity = lower(Severity.MEDIUM) if forwarded else Severity.MEDIUM
                findings.append(
                    Finding(
                        id=f"{self.name}.invalid",
                        check=self.name,
                        severity=severity,
                        title=f"Broken DKIM signature from {signer}",
                        explanation=(
                            f"The message carries a DKIM signature from {signer}, but it doesn't "
                            f"check out: {sig.reason}. Someone may have altered the message after "
                            "it was signed."
                            + (
                                " It came through a mailing list, which often edits the subject "
                                "or adds a footer and breaks signatures that way."
                                if forwarded
                                else ""
                            )
                        ),
                        evidence=proof,
                    )
                )

        valid = [s for s in signatures if s.status == "pass" and s.domain]
        aligned = [s for s in valid if from_domain and same_owner(s.domain or "", from_domain)]
        if from_domain and valid and not aligned:
            signers = ", ".join(dict.fromkeys(s.domain or "" for s in valid))
            findings.append(
                Finding(
                    id=f"{self.name}.other_domain",
                    check=self.name,
                    severity=Severity.INFO,
                    title="Signed, but by a different domain",
                    explanation=(
                        f"The message is validly signed by {signers}, which isn't the domain in "
                        f"From ({from_domain}). That's normal for mail sent through a service "
                        f"such as a newsletter platform, but the signature says nothing about "
                        f"{from_domain} itself."
                    ),
                    evidence=(
                        *evidence.header(msg, "From"),
                        *(evidence.from_field(f) for f in fields),
                    ),
                )
            )
        return findings
