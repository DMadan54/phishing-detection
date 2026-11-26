"""Is the Date header believable?

The sender's software writes Date, so it can say anything. The useful
comparison isn't with today (analysing a year-old email is normal) but with
when the message actually arrived, which the trusted Received hop records.
A message dated well after it arrived, or months before, was most likely
written by a tool with a made-up date.

Without a usable Received timestamp only "in the future" can be checked,
against the current time.
"""

from dataclasses import dataclass, field
from datetime import datetime

from phishlens.email import evidence
from phishlens.email.config import EmailConfig
from phishlens.email.parse import ParsedEmail
from phishlens.email.received import sending_hop
from phishlens.findings import CheckContext, Finding, HeaderEvidence, Severity


@dataclass(frozen=True)
class DateCheck:
    config: EmailConfig = field(default_factory=EmailConfig)
    name: str = "email.date"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        proof = tuple(evidence.header(msg, "Date"))
        if msg.date is None:
            missing = msg.header("Date") is None
            return [
                self._finding(
                    "invalid",
                    Severity.LOW,
                    "No date" if missing else "Unreadable date",
                    "The message has no Date header, which all mail software adds."
                    if missing
                    else "The Date header isn't a valid date, which ordinary mail software "
                    "never produces.",
                    proof,
                )
            ]

        received_at = self._received_at(msg)
        reference = received_at or ctx.clock.now()
        when = "it arrived" if received_at else "now"

        if msg.date > reference + self.config.future_tolerance:
            days = (msg.date - reference).days
            return [
                self._finding(
                    "future",
                    Severity.MEDIUM,
                    "Dated in the future",
                    f"The message is dated {msg.date:%d %b %Y}, {days} days after {when}. "
                    "Real mail software takes the date from the computer's clock, so a future "
                    "date points to a tool that made one up.",
                    proof,
                )
            ]
        if received_at and msg.date < received_at - self.config.stale_after:
            days = (received_at - msg.date).days
            return [
                self._finding(
                    "stale",
                    Severity.LOW,
                    "Dated long before it arrived",
                    f"The message is dated {msg.date:%d %b %Y}, {days} days before it arrived. "
                    "Ordinary mail arrives within minutes; a much older date can mean an old "
                    "message re-sent by a bulk tool.",
                    proof,
                )
            ]
        return []

    def _received_at(self, msg: ParsedEmail) -> datetime | None:
        hop = sending_hop(msg.received, self.config.trusted_receivers)
        if hop and hop.timestamp:
            return hop.timestamp
        return next((h.timestamp for h in msg.received if h.timestamp), None)

    def _finding(
        self,
        what: str,
        severity: Severity,
        title: str,
        explanation: str,
        proof: tuple[HeaderEvidence, ...],
    ) -> Finding:
        return Finding(
            id=f"{self.name}.{what}",
            check=self.name,
            severity=severity,
            title=title,
            explanation=explanation,
            evidence=proof,
        )
