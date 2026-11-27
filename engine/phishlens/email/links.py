"""Links in the message body.

Two kinds of finding come from here:

- email.links.text_mismatch, which only makes sense in an email: link text
  that shows one domain while the link goes to another ("www.paypal.com"
  pointing at evil.example), the oldest phishing trick there is.
- Every URL check that only reads a link (phishlens.url: lexical checks,
  lookalikes, international names, and reputation if configured), run on
  each distinct link. Those findings keep their own url.* ids, so a lookalike
  domain is reported the same way whether it was pasted or found in an email.
  Findings with the same id are merged, with up to five links as evidence.

Links are parsed with the same browser rules as pasted URLs. They are never
fetched: following a phishing link can tell the attacker that the message
was opened.
"""

import asyncio
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from phishlens.domains import normalise_domain, same_owner
from phishlens.email.parse import Link, ParsedEmail
from phishlens.findings import (
    BodyEvidence,
    Check,
    CheckContext,
    Evidence,
    Finding,
    Severity,
    UrlEvidence,
)
from phishlens.runner import run_checks
from phishlens.url.domain_checks import IdnCheck, LookalikeCheck
from phishlens.url.lexical import lexical_checks
from phishlens.url.parse import ParsedUrl, parse_url

MAX_EXAMPLES = 5
MAX_LINKS = 20  # distinct links checked per message; the rest add nothing new

# Link text that is, as a whole, a URL or a bare domain.
_DOMAIN_TEXT = re.compile(
    r"^(?:https?://)?(?P<host>(?:[a-z0-9-]+\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+))\.?(?:[/:?#]\S*)?$",
    re.IGNORECASE,
)


def reading_checks() -> tuple[Check[ParsedUrl], ...]:
    """URL checks that need nothing but the link text."""
    return (*lexical_checks(), LookalikeCheck(), IdnCheck())


@dataclass(frozen=True)
class LinkCheck:
    url_checks: Sequence[Check[ParsedUrl]] = field(default_factory=reading_checks)
    name: str = "email.links"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        links: dict[str, Link] = {}
        for link in msg.links:
            links.setdefault(link.href.strip(), link)
        distinct = list(links.items())[:MAX_LINKS]
        parsed = [(parse_url(href), link) for href, link in distinct]
        return [*self._text_mismatch(parsed), *await self._url_findings(parsed, ctx)]

    def _text_mismatch(self, links: list[tuple[ParsedUrl, Link]]) -> list[Finding]:
        examples: list[tuple[str, str]] = []
        for url, link in links:
            if link.source != "html" or not url.host:
                continue
            match = _DOMAIN_TEXT.match(link.text.strip())
            if not match:
                continue
            shown = normalise_domain(match.group("host"))
            if shown and not same_owner(shown, url.host):
                examples.append((link.text.strip(), url.host))
        if not examples:
            return []
        shown, real = examples[0]
        return [
            Finding(
                id=f"{self.name}.text_mismatch",
                check=self.name,
                severity=Severity.HIGH,
                title="A link shows one address but goes to another",
                explanation=(
                    f"A link reads '{shown}' but actually goes to {real}. Showing a trusted "
                    "address while linking somewhere else is a classic phishing trick."
                    + _more(len(examples))
                ),
                evidence=tuple(
                    e
                    for text, host in examples[:MAX_EXAMPLES]
                    for e in (BodyEvidence(excerpt=text), UrlEvidence(component="host", value=host))
                ),
            )
        ]

    async def _url_findings(
        self, links: list[tuple[ParsedUrl, Link]], ctx: CheckContext
    ) -> list[Finding]:
        per_link = await asyncio.gather(
            *(run_checks(self.url_checks, url, ctx) for url, _ in links)
        )
        grouped: dict[str, list[tuple[Finding, Link]]] = {}
        for (_, link), findings in zip(links, per_link, strict=True):
            for finding in findings:
                grouped.setdefault(finding.id, []).append((finding, link))
        return [_merge(items) for items in grouped.values()]


def _more(count: int) -> str:
    return f" ({count} such links in total.)" if count > 1 else ""


def _merge(items: list[tuple[Finding, Link]]) -> Finding:
    """One finding per id: the first link's explanation, every link's evidence."""
    first, _ = items[0]
    evidence: list[Evidence] = []
    for finding, link in items[:MAX_EXAMPLES]:
        if link.text and link.text != link.href:
            evidence.append(BodyEvidence(excerpt=f"link text: {link.text}"))
        evidence.extend(finding.evidence)
    worst = max((f.severity for f, _ in items), key=list(Severity).index)
    return first.model_copy(
        update={
            "severity": worst,
            "explanation": first.explanation + _more(len(items)),
            "evidence": tuple(evidence),
        }
    )
