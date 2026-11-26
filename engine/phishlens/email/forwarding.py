"""Mailing lists and forwarding: the main false-positive source for SPF,
DKIM and DMARC.

A list resends the message from its own server (so SPF is for the list, not
the original sender) and often edits the subject or adds a footer (which
breaks the original DKIM signature). ARC lets the list record what the
authentication looked like when it received the message, sealed with its own
signature. When List-Id is present and the ARC chain validates, the
authentication checks lower their severity one step and this check explains
why.

An attacker can add a List-Id and seal their own message, which is why it's
only one step down. Trusting only known list operators' seals would close
that gap; that's future work.
"""

from dataclasses import dataclass

from phishlens.email import evidence
from phishlens.email.auth import is_mailing_list
from phishlens.email.parse import ParsedEmail
from phishlens.findings import CheckContext, Finding, Severity


@dataclass(frozen=True)
class ForwardingCheck:
    name: str = "email.forwarding"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        if not await is_mailing_list(msg, ctx):
            return []
        return [
            Finding(
                id=f"{self.name}.mailing_list",
                check=self.name,
                severity=Severity.INFO,
                title="Delivered through a mailing list",
                explanation=(
                    f"The message came through the mailing list {msg.list_id}, which recorded "
                    "its authentication results in a valid ARC seal. Lists often break SPF "
                    "and DKIM for the original sender, so those findings are less serious here."
                ),
                evidence=(*evidence.header(msg, "List-Id"), *evidence.header(msg, "ARC-Seal")),
            )
        ]
