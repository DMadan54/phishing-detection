"""Where does the link really end up?

Phishing links often bounce through several addresses: a URL shortener, a
compromised site, a "please wait" page that redirects with a meta tag or a
line of script, and only then the fake sign-in page. Each hop can be on a
different domain, which helps the link slip past filters that only look at
the first address.

The chain is followed by phishlens.net.safe_fetch, which refuses every
internal address before connecting (SSRF protection) and never runs script.
Only /analyse/url follows redirects. Links inside emails are not fetched,
because fetching a phishing link can tell the attacker the email was read.
"""

from dataclasses import dataclass, field

from phishlens.brands import load_shorteners
from phishlens.domains import same_owner
from phishlens.findings import BodyEvidence, CheckContext, Finding, Severity
from phishlens.services import RedirectChain
from phishlens.url.lookalike import LookalikeDetector, default_detector
from phishlens.url.parse import ParsedUrl, parse_url

KIND_WORDS = {
    "start": "start",
    "http": "redirect",
    "meta_refresh": "meta refresh",
    "script": "script redirect",
}


def hop_evidence(chain: RedirectChain) -> tuple[BodyEvidence, ...]:
    lines = []
    for number, hop in enumerate(chain.hops, start=1):
        status = f"{hop.status} " if hop.status else ""
        lines.append(BodyEvidence(excerpt=f"{number}. {status}{hop.url} ({KIND_WORDS[hop.kind]})"))
    return tuple(lines)


@dataclass(frozen=True)
class RedirectCheck:
    detector: LookalikeDetector = field(default_factory=default_detector)
    name: str = "url.redirect"
    timeout: float = 25.0  # longer than the fetcher's own 20-second limit

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.scheme not in ("http", "https"):
            return []
        chain = await ctx.fetcher.follow(url.href)
        proof = hop_evidence(chain)
        out: list[Finding] = []

        def add(what: str, severity: Severity, title: str, explanation: str) -> None:
            out.append(
                Finding(
                    id=f"{self.name}.{what}",
                    check=self.name,
                    severity=severity,
                    title=title,
                    explanation=explanation,
                    evidence=proof,
                )
            )

        hops = [parse_url(h.url) for h in chain.hops]
        final = hops[-1]
        if len(chain.hops) > 1:
            add(
                "chain",
                Severity.INFO,
                f"Redirects {len(chain.hops) - 1} time(s)",
                f"The link passes through {len(chain.hops) - 1} redirect(s) and "
                + (
                    f"ends at {final.host_unicode or final.href}."
                    if chain.stopped == "done"
                    else "was stopped before the end (see below)."
                ),
            )

        shorteners = load_shorteners()
        hidden = [h for h in hops[1:] if h.host.removeprefix("www.") in shorteners]
        if hidden:
            add(
                "shortener",
                Severity.LOW,
                "Passes through a URL shortener",
                f"Part-way along, the link goes through {hidden[0].host}, a URL shortener. "
                "Chaining shorteners hides the destination from filters.",
            )

        for kind, what, word in (
            ("meta_refresh", "meta_refresh", "a meta refresh tag"),
            ("script", "script", "a line of script"),
        ):
            hop = next((h for h in chain.hops if h.kind == kind), None)
            if hop:
                add(
                    what,
                    Severity.MEDIUM,
                    "Redirects from inside the page",
                    f"A page along the way sends the browser on with {word} instead of a normal "
                    f"redirect (to {hop.url}). That's a common way to get past link scanners, "
                    "which often don't look inside pages. It was read as text, never run.",
                )

        start = hops[0]
        for step in hops[1:]:
            if not step.host or (start.host and same_owner(step.host, start.host)):
                continue
            match = self.detector.check(step.host)
            if match:
                out.append(
                    Finding(
                        id=f"{self.name}.to_lookalike",
                        check=self.name,
                        severity=Severity.HIGH,
                        title=f"Ends up at a lookalike of {match.brand.name}",
                        explanation=(
                            f"The link starts at {start.host_unicode or start.href} but leads to "
                            f"{match.domain_unicode}, which imitates {match.genuine}: it "
                            f"{match.reason}."
                        ),
                        evidence=(*proof, match.evidence()),
                    )
                )
                break

        if chain.stopped == "blocked":
            add(
                "blocked",
                Severity.MEDIUM,
                "Tried to reach an internal address",
                f"The link led to an address that isn't on the public internet: {chain.detail}. "
                "PhishLens refused to follow it. Public links have no reason to point at private "
                "networks; this can be an attempt to reach systems behind a firewall.",
            )
        elif chain.stopped in ("too_many", "loop"):
            add(
                "too_many",
                Severity.MEDIUM,
                "Too many redirects",
                "The link keeps redirecting ("
                + ("round in a circle" if chain.stopped == "loop" else chain.detail + " hops")
                + "). Long chains are used to wear down scanners.",
            )
        elif chain.stopped in ("error", "timeout", "not_http"):
            add(
                "error",
                Severity.INFO,
                "Couldn't follow the link to the end",
                f"Following the link stopped early: {chain.detail}. The other checks still "
                "apply to the address itself.",
            )
        return out
