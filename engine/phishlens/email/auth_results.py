"""Authentication-Results headers, and why we mostly ignore them.

These headers record what a receiving server concluded about SPF, DKIM and
DMARC. They're useful when written by the recipient's own provider, but a
sender can type the same header into their message ("dkim=pass for
paypal.com") hoping a filter or a person will believe it. So:

- a header is trusted only if its authserv-id is configured as trusted;
- untrusted headers are reported (INFO) and otherwise ignored;
- any header that claims a pass our own checks can't reproduce is
  reported as a contradiction, because a false claim of success is itself
  a sign of forgery. Headers recorded by a mailing list that sealed them
  with a valid ARC chain are exempt: they describe the message before the
  list changed it.
"""

import logging
from dataclasses import dataclass, field

import authres

from phishlens.domains import normalise_domain, same_owner
from phishlens.email import evidence
from phishlens.email.auth import evaluate_dmarc, evaluate_spf, verify_arc, verify_dkim
from phishlens.email.config import EmailConfig
from phishlens.email.parse import HeaderField, ParsedEmail
from phishlens.findings import CheckContext, Finding, Severity


@dataclass(frozen=True, slots=True)
class Claim:
    method: str  # "spf", "dkim", "dmarc", ...
    result: str  # "pass", "fail", ...
    domain: str | None  # header.d, smtp.mailfrom or header.from, whichever applies


@dataclass(frozen=True, slots=True)
class AuthResults:
    authserv_id: str
    claims: tuple[Claim, ...]
    field: HeaderField


logger = logging.getLogger(__name__)

_DOMAIN_PROPERTY = {"dkim": "d", "spf": "mailfrom", "dmarc": "from"}


def parse_auth_results(msg: ParsedEmail) -> list[AuthResults]:
    parsed: list[AuthResults] = []
    for header_field in msg.headers_named("Authentication-Results"):
        try:
            header = authres.AuthenticationResultsHeader.parse(
                f"Authentication-Results: {header_field.value}"
            )
        except Exception as exc:
            # Unparseable: there's nothing to believe or contradict.
            logger.debug("skipping unparseable Authentication-Results (%s)", type(exc).__name__)
            continue
        claims = []
        for result in header.results:
            method = str(result.method).lower()
            wanted = _DOMAIN_PROPERTY.get(method)
            domain = None
            for prop in result.properties:
                if prop.name == wanted:
                    value = str(prop.value).rpartition("@")[2]
                    domain = normalise_domain(value)
            claims.append(Claim(method, str(result.result).lower(), domain))
        parsed.append(AuthResults(str(header.authserv_id).lower(), tuple(claims), header_field))
    return parsed


def trusted_dmarc_pass(results: list[AuthResults], config: EmailConfig, from_domain: str) -> bool:
    """Did a trusted receiver record DMARC passing for this From domain?"""
    return any(
        claim.method == "dmarc" and claim.result == "pass" and claim.domain == from_domain
        for r in results
        if r.authserv_id in config.trusted_authserv_ids
        for claim in r.claims
    )


@dataclass(frozen=True)
class AuthResultsCheck:
    config: EmailConfig = field(default_factory=EmailConfig)
    name: str = "email.auth_results"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        results = parse_auth_results(msg)
        if not results:
            return []
        findings: list[Finding] = []

        untrusted = [r for r in results if r.authserv_id not in self.config.trusted_authserv_ids]
        if untrusted:
            ids = ", ".join(dict.fromkeys(r.authserv_id for r in untrusted))
            findings.append(
                Finding(
                    id=f"{self.name}.untrusted",
                    check=self.name,
                    severity=Severity.INFO,
                    title="Ignored authentication claims in the headers",
                    explanation=(
                        f"The message carries Authentication-Results headers from {ids}. Anyone "
                        "can write these headers, so they're ignored and PhishLens checks SPF, "
                        "DKIM and DMARC itself."
                    ),
                    evidence=tuple(evidence.from_field(r.field) for r in untrusted),
                )
            )

        sealers = await self._arc_sealers(msg, ctx)
        contradictions: list[tuple[AuthResults, Claim, str]] = []
        for r in untrusted:
            if r.authserv_id in sealers:
                continue
            for claim in r.claims:
                if claim.result != "pass":
                    continue
                why = await self._contradiction(msg, ctx, claim)
                if why:
                    contradictions.append((r, claim, why))
        if contradictions:
            first, claim, why = contradictions[0]
            findings.append(
                Finding(
                    id=f"{self.name}.contradicted",
                    check=self.name,
                    severity=Severity.HIGH,
                    title="A header claims checks passed that didn't",
                    explanation=(
                        f"A header written by {first.authserv_id} claims {claim.method}=pass"
                        + (f" for {claim.domain}" if claim.domain else "")
                        + f", but {why}. Planting a fake 'everything passed' header is a known "
                        "way to fool filters and people."
                    ),
                    evidence=tuple(
                        dict.fromkeys(evidence.from_field(r.field) for r, _, _ in contradictions)
                    ),
                )
            )
        return findings

    async def _arc_sealers(self, msg: ParsedEmail, ctx: CheckContext) -> frozenset[str]:
        if await verify_arc(msg, ctx) != "pass":
            return frozenset()
        domains = set()
        for seal in msg.headers_named("ARC-Seal"):
            for tag in seal.value.split(";"):
                name, _, value = tag.partition("=")
                if name.strip().lower() == "d":
                    domains.add(value.strip().lower())
        return frozenset(domains)

    async def _contradiction(self, msg: ParsedEmail, ctx: CheckContext, claim: Claim) -> str | None:
        """Why our own result disagrees with a claimed pass, or None."""
        if claim.method == "dkim":
            signatures = await verify_dkim(msg, ctx)
            if not signatures:
                return "the message has no DKIM signature at all"
            passing = [s.domain for s in signatures if s.status == "pass" and s.domain]
            if claim.domain and not any(d == claim.domain for d in passing):
                return f"no valid signature from {claim.domain} is present"
            return None
        if claim.method == "spf":
            outcome = await evaluate_spf(msg, ctx, self.config)
            if outcome.result is None:
                return None  # nothing to compare against
            if outcome.result != "pass":
                return f"SPF actually gives {outcome.result} for the delivering server"
            if claim.domain and outcome.domain and not same_owner(claim.domain, outcome.domain):
                return f"SPF only passes for {outcome.domain}"
            return None
        if claim.method == "dmarc":
            sender = msg.from_address
            if not sender or not sender.domain:
                return None
            evaluation = await evaluate_dmarc(msg, ctx, self.config, sender.domain)
            if not evaluation.passed:
                return f"DMARC doesn't pass for {sender.domain}"
        return None
