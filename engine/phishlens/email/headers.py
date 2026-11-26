"""Do the other identity headers agree with From?

- Reply-To decides where your answer goes. Pointing it somewhere else lets a
  scammer receive replies even when the From address is spoofed or borrowed.
- Return-Path is the bounce address. Mail services often use their own
  domain for it, so a mismatch alone means little (INFO).
- Message-ID is made up by the sending software, usually with its own
  domain after the @. One that belongs to nobody involved can hint that the
  message was produced by a bulk-sending tool rather than the claimed sender.

Domains are compared by organisational domain, so help.shop.example and
shop.example agree.
"""

from dataclasses import dataclass

from phishlens.domains import domain_of_address, normalise_domain, same_owner
from phishlens.email import evidence
from phishlens.email.auth import is_mailing_list, lower
from phishlens.email.parse import ParsedEmail
from phishlens.findings import CheckContext, Finding, HeaderEvidence, Severity


@dataclass(frozen=True)
class HeaderConsistencyCheck:
    name: str = "email.headers"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        sender = msg.from_address
        findings: list[Finding] = []
        if not msg.message_id:
            findings.append(
                self._finding(
                    "message_id_missing",
                    Severity.LOW,
                    "No Message-ID",
                    "Almost every mail program adds a Message-ID header. Its absence suggests "
                    "the message was put together by a script rather than ordinary mail software.",
                    (*evidence.header(msg, "From"),),
                )
            )
        if sender is None or sender.domain is None:
            return findings
        from_domain = sender.domain

        for reply_to in msg.reply_to:
            if reply_to.domain and not same_owner(reply_to.domain, from_domain):
                forwarded = await is_mailing_list(msg, ctx)
                findings.append(
                    self._finding(
                        "reply_to_mismatch",
                        lower(Severity.MEDIUM) if forwarded else Severity.MEDIUM,
                        "Replies go to a different domain",
                        f"Replies would go to {reply_to.addr_spec}, not to {from_domain}, the "
                        "domain the message says it's from. Scammers do this so your answer "
                        "reaches them even when the From address is spoofed."
                        + (
                            " This message came through a mailing list, which often sets "
                            "Reply-To to the list."
                            if forwarded
                            else ""
                        ),
                        (*evidence.header(msg, "From"), *evidence.header(msg, "Reply-To")),
                    )
                )
                break

        bounce = domain_of_address(msg.return_path) if msg.return_path else None
        if bounce and not same_owner(bounce, from_domain):
            findings.append(
                self._finding(
                    "return_path_mismatch",
                    Severity.INFO,
                    "Bounces go to a different domain",
                    f"Undeliverable-mail notices go to {bounce}, not {from_domain}. Email "
                    "services commonly do this, so on its own it means little; DMARC checks "
                    "whether it matters.",
                    (*evidence.header(msg, "From"), *evidence.header(msg, "Return-Path")),
                )
            )

        id_domain = self._message_id_domain(msg)
        if id_domain and not self._related(id_domain, msg, from_domain, bounce):
            findings.append(
                self._finding(
                    "message_id_unrelated",
                    Severity.LOW,
                    "Message-ID from an unrelated system",
                    f"The Message-ID was made by {id_domain}, which isn't the sender's domain, "
                    "the bounce domain or a signing domain. Mail is usually given its ID by "
                    "the sender's own system.",
                    (*evidence.header(msg, "From"), *evidence.header(msg, "Message-ID")),
                )
            )
        return findings

    @staticmethod
    def _message_id_domain(msg: ParsedEmail) -> str | None:
        if not msg.message_id or "@" not in msg.message_id:
            return None
        domain = normalise_domain(msg.message_id.rpartition("@")[2])
        return domain if domain and "." in domain else None

    @staticmethod
    def _related(id_domain: str, msg: ParsedEmail, from_domain: str, bounce: str | None) -> bool:
        signers = []
        for header in msg.headers_named("DKIM-Signature"):
            for tag in header.value.split(";"):
                name, _, value = tag.partition("=")
                if name.strip().lower() == "d":
                    signers.append(value.strip().lower())
        related = [from_domain, *([bounce] if bounce else []), *signers]
        return any(same_owner(id_domain, d) for d in related)

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
