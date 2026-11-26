"""SPF: was the delivering server allowed to send for the envelope domain?

What it proves: the server whose IP is recorded in the trusted Received hop
is on the list the envelope domain (Return-Path) publishes. What it doesn't
prove: anything about the From address people see. DMARC links the two.
"""

from dataclasses import dataclass, field

from phishlens.email import evidence
from phishlens.email.auth import evaluate_spf, is_mailing_list, lower
from phishlens.email.config import EmailConfig
from phishlens.email.parse import ParsedEmail
from phishlens.findings import CheckContext, Finding, Severity


@dataclass(frozen=True)
class SpfCheck:
    config: EmailConfig = field(default_factory=EmailConfig)
    name: str = "email.spf"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        outcome = await evaluate_spf(msg, ctx, self.config)
        hop_evidence = evidence.header(msg, "Received", outcome.hop.index) if outcome.hop else []
        proof = (*evidence.header(msg, "Return-Path"), *hop_evidence)
        domain = outcome.domain or "the sender's domain"
        ip = str(outcome.hop.from_ip) if outcome.hop else "the sending server"

        def finding(what: str, severity: Severity, title: str, explanation: str) -> Finding:
            return Finding(
                id=f"{self.name}.{what}",
                check=self.name,
                severity=severity,
                title=title,
                explanation=explanation,
                evidence=proof,
            )

        match outcome.result:
            case None:
                return [
                    finding(
                        "no_sending_ip",
                        Severity.INFO,
                        "Couldn't tell which server delivered this",
                        "There's no usable Received header recording which server handed this "
                        "message over, so SPF couldn't be checked.",
                    )
                ]
            case "fail":
                forwarded = await is_mailing_list(msg, ctx)
                return [
                    finding(
                        "fail",
                        lower(Severity.MEDIUM) if forwarded else Severity.MEDIUM,
                        "Sent from a server the domain doesn't allow",
                        f"The server at {ip} isn't on the list of servers allowed to send mail "
                        f"for {domain}. Either someone else sent it using that address, or it "
                        "was forwarded on the way."
                        + (
                            " It came through a mailing list, which often causes this."
                            if forwarded
                            else ""
                        ),
                    )
                ]
            case "softfail":
                return [
                    finding(
                        "softfail",
                        Severity.LOW,
                        "Sent from a server the domain doesn't expect",
                        f"{domain} says {ip} probably shouldn't be sending its mail, but asks "
                        "receivers not to reject it outright.",
                    )
                ]
            case "none":
                return [
                    finding(
                        "none",
                        Severity.LOW,
                        "The sender's domain publishes no SPF record",
                        f"{domain} doesn't say which servers may send its mail, so there's no way "
                        f"to check whether {ip} was allowed to.",
                    )
                ]
            case "permerror" | "temperror":
                reason = (
                    "its SPF record is broken"
                    if outcome.result == "permerror"
                    else "a DNS lookup failed"
                )
                return [
                    finding(
                        "error",
                        Severity.LOW,
                        "SPF couldn't be checked",
                        f"SPF for {domain} couldn't be evaluated because {reason}.",
                    )
                ]
            case _:
                return []  # pass, or neutral (the domain makes no claim)
