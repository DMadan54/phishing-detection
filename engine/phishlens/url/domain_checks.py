"""Checks on what the domain name looks like: lookalikes and international names.

- url.lookalike: the domain imitates a brand (see lookalike.py for the
  rules). The finding names the brand and puts both domains side by side.
- url.idn: internationalised names. Punycode ("xn--...") is how non-ASCII
  names are stored in DNS; the report shows the decoded name people see. A
  label mixing scripts (Latin with Cyrillic, say) is flagged on its own,
  whether or not it imitates a known brand.
"""

from dataclasses import dataclass, field

from phishlens.findings import CheckContext, Finding, Severity, UrlEvidence
from phishlens.url.lookalike import LookalikeDetector, Rule, default_detector
from phishlens.url.parse import ParsedUrl
from phishlens.url.unicode_data import is_mixed_script, scripts_in

SEVERITY: dict[Rule, Severity] = {
    "homograph": Severity.CRITICAL,
    "character_swap": Severity.HIGH,
    "tld_swap": Severity.HIGH,
    "typo": Severity.HIGH,
    "combo": Severity.MEDIUM,
}

TITLE: dict[Rule, str] = {
    "homograph": "Uses look-alike letters from another alphabet",
    "character_swap": "Swaps in characters that look the same",
    "tld_swap": "The right name with the wrong ending",
    "typo": "A misspelling of a well-known name",
    "combo": "A well-known name with extra words added",
}


@dataclass(frozen=True)
class LookalikeCheck:
    detector: LookalikeDetector = field(default_factory=default_detector)
    name: str = "url.lookalike"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.domain is None:
            return []
        match = self.detector.check(url.host)
        if match is None:
            return []
        return [
            Finding(
                id=f"{self.name}.{match.rule}",
                check=self.name,
                severity=SEVERITY[match.rule],
                title=f"{TITLE[match.rule]}: imitates {match.brand.name}",
                explanation=(
                    f"{match.domain_unicode} looks like {match.genuine} ({match.brand.name}) but "
                    f"isn't: it {match.reason}. Lookalike names are registered to make a fake "
                    "site pass a quick glance."
                ),
                evidence=(
                    match.evidence(),
                    UrlEvidence(component="host", value=url.host, span=url.span_of(url.raw_host)),
                ),
            )
        ]


@dataclass(frozen=True)
class IdnCheck:
    name: str = "url.idn"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.domain is None or "xn--" not in url.host:
            return []
        proof = UrlEvidence(
            component="host", value=url.host_unicode, span=url.span_of(url.raw_host)
        )
        out = [
            Finding(
                id=f"{self.name}.punycode",
                check=self.name,
                severity=Severity.INFO,
                title="An international domain name",
                explanation=(
                    f"The site name is stored as {url.host} and displayed as {url.host_unicode}. "
                    "International names are normal; this is shown so you can see both forms."
                ),
                evidence=(proof,),
            )
        ]
        for label in url.host_unicode.split("."):
            if is_mixed_script(label):
                alphabets = " and ".join(sorted(scripts_in(label)))
                out.append(
                    Finding(
                        id=f"{self.name}.mixed_script",
                        check=self.name,
                        severity=Severity.HIGH,
                        title="Mixes letters from different alphabets",
                        explanation=(
                            f"The part '{label}' mixes {alphabets} letters in one word. Real "
                            "names almost never do that; it's how look-alike letters are "
                            "slipped into familiar-looking words."
                        ),
                        evidence=(proof,),
                    )
                )
                break
        return out
