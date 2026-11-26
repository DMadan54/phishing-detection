"""Checks that ask outside services about a domain: age, certificates, reputation.

All three skip domains that a brand owns or that are in the popular set:
they are long established, and asking about them only adds requests and
sends more data to third parties.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from phishlens.brands import brand_owning
from phishlens.findings import CheckContext, Finding, Severity, UrlEvidence
from phishlens.intel.reputation import ReputationSource
from phishlens.services import ServiceNotConfiguredError, ServiceUnavailableError
from phishlens.url.lookalike import default_detector
from phishlens.url.parse import ParsedUrl

VERY_NEW = timedelta(days=7)
NEW = timedelta(days=30)
NEW_CERTIFICATE = timedelta(days=7)


def _established(url: ParsedUrl) -> bool:
    if url.domain is None:
        return True  # IPs and hostless URLs have no registration to look up
    return (
        brand_owning(url.host) is not None or url.domain.registrable in default_detector().popular
    )


def _ago(days: int) -> str:
    if days <= 0:
        return "today"
    return "yesterday" if days == 1 else f"{days} days ago"


def _proof(url: ParsedUrl) -> tuple[UrlEvidence]:
    registrable = url.domain.registrable if url.domain else url.host
    return (UrlEvidence(component="host", value=registrable, span=url.span_of(registrable)),)


@dataclass(frozen=True)
class AgeCheck:
    name: str = "url.age"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.domain is None or _established(url):
            return []
        domain = url.domain.registrable
        try:
            record = await ctx.rdap.lookup_domain(domain)
        except (ServiceUnavailableError, ServiceNotConfiguredError) as exc:
            return [self._unknown(url, f"its registry couldn't be asked ({exc})")]
        if record is None or record.registered is None:
            return [self._unknown(url, "the registry has no registration date for it")]

        age = ctx.clock.now() - record.registered
        if age > NEW:
            return []
        when = f"{_ago(age.days)} (on {record.registered:%d %b %Y})"
        return [
            Finding(
                id=f"{self.name}.new",
                check=self.name,
                severity=Severity.HIGH if age <= VERY_NEW else Severity.MEDIUM,
                title=f"Registered {_ago(age.days)}",
                explanation=(
                    f"{domain} was registered {when}. Phishing sites are set up just before "
                    "they're used and abandoned within days, so a very new domain is one of the "
                    "strongest warning signs there is. Real organisations' sites are usually "
                    "years old."
                ),
                evidence=_proof(url),
            )
        ]

    def _unknown(self, url: ParsedUrl, why: str) -> Finding:
        registrable = url.domain.registrable if url.domain else url.host
        return Finding(
            id=f"{self.name}.unknown",
            check=self.name,
            severity=Severity.INFO,
            title="Couldn't find out how old the domain is",
            explanation=f"The age of {registrable} is unknown: {why}.",
            evidence=_proof(url),
        )


@dataclass(frozen=True)
class CertificateCheck:
    name: str = "url.ct"
    timeout: float = 15.0  # crt.sh is slow, and requests may wait for the rate limiter

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.scheme != "https" or url.domain is None or _established(url):
            return []
        domain = url.domain.registrable
        try:
            first = await ctx.ct.first_certificate(domain)
        except (ServiceUnavailableError, ServiceNotConfiguredError) as exc:
            return [self._unknown(url, f"the certificate logs couldn't be searched ({exc})")]
        if first is None:
            return [self._unknown(url, "no certificate for it appears in the public logs yet")]
        age = ctx.clock.now() - first
        if age > NEW_CERTIFICATE:
            return []
        return [
            Finding(
                id=f"{self.name}.first_seen_recent",
                check=self.name,
                severity=Severity.MEDIUM,
                title="Its first security certificate is brand new",
                explanation=(
                    f"The first HTTPS certificate for {domain} was issued {_ago(age.days)} (on "
                    f"{first:%d %b %Y}), according to the public certificate-transparency logs. "
                    "That's usually when a site goes live, so this site is days old."
                ),
                evidence=_proof(url),
            )
        ]

    def _unknown(self, url: ParsedUrl, why: str) -> Finding:
        registrable = url.domain.registrable if url.domain else url.host
        return Finding(
            id=f"{self.name}.unknown",
            check=self.name,
            severity=Severity.INFO,
            title="Couldn't check the certificate history",
            explanation=f"The certificate history of {registrable} is unknown: {why}.",
            evidence=_proof(url),
        )


@dataclass(frozen=True)
class ReputationCheck:
    sources: Sequence[ReputationSource] = field(default_factory=tuple)
    name: str = "url.reputation"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or not self.sources or url.scheme not in ("http", "https"):
            return []
        findings = []
        for source in self.sources:
            try:
                verdict = await source.lookup(url)
            except ServiceUnavailableError:
                continue  # a source that can't answer says nothing either way
            if verdict is None:
                continue
            findings.append(
                Finding(
                    id=f"{self.name}.{verdict.finding}",
                    check=self.name,
                    severity=verdict.severity,
                    title=f"Flagged by {verdict.source}",
                    explanation=f"{verdict.source} {verdict.summary}.",
                    evidence=(
                        UrlEvidence(component="host", value=url.host, span=url.span_of(url.host)),
                    ),
                )
            )
        return findings
