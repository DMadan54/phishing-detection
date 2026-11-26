"""Checks that read the URL text itself. Nothing is fetched.

Each class is one small check, named after the part of the URL it looks at,
so finding ids follow the usual <check name>.<what> pattern:

- url.parse: the URL can't be read the way a browser would.
- url.scheme: javascript:, data:, vbscript: and file: run or open content
  directly instead of going to a website.
- url.host: bare IPs (in any spelling a browser accepts), percent-encoded
  hosts nobody can read, very deep or very long hostnames, random-looking
  names, and URL shorteners.
- url.userinfo: "https://paypal.com@evil.example" really goes to
  evil.example. Everything before @ is a username, but people read it as
  the site.
- url.brand: a brand named in the subdomain or path of someone else's
  domain, as in login.microsoft.com.evil.example.
- url.tld: TLDs that are heavily over-represented in phishing.
- url.port: an unusual port number.
"""

import math
from collections import Counter
from dataclasses import dataclass
from functools import cache

from phishlens.brands import brands_in_token_text, load_shorteners, read_shared
from phishlens.findings import CheckContext, Finding, Severity, UrlComponent, UrlEvidence
from phishlens.url.parse import ParsedUrl

DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})
MAX_SUBDOMAIN_LABELS = 4
LONG_HOST = 60
ENTROPY_MIN_LENGTH = 12
ENTROPY_BITS = 3.5
LOGIN_WORDS = ("login", "signin", "sign-in", "verify", "account", "secure", "update", "password")


@cache
def suspicious_tlds() -> frozenset[str]:
    data = read_shared("suspicious-tlds.json")
    return frozenset(str(t).lower() for t in data["tlds"])


def entropy(text: str) -> float:
    """Shannon entropy in bits per character: how unpredictable the letters are.

    English-like names score about 2.5 to 3.2; random strings of letters and
    digits, as made by domain-generation algorithms, score 3.5 or more.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def url_evidence(url: ParsedUrl, component: UrlComponent, value: str) -> UrlEvidence:
    return UrlEvidence(component=component, value=value, span=url.span_of(value))


def _finding(
    check: str, what: str, severity: Severity, title: str, explanation: str, *proof: UrlEvidence
) -> Finding:
    return Finding(
        id=f"{check}.{what}",
        check=check,
        severity=severity,
        title=title,
        explanation=explanation,
        evidence=proof,
    )


@dataclass(frozen=True)
class ParseCheck:
    name: str = "url.parse"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if url.valid:
            return []
        return [
            _finding(
                self.name,
                "invalid",
                Severity.MEDIUM,
                "Not a valid web address",
                "This can't be read as a web address the way a browser reads one. Broken "
                "addresses are sometimes used to confuse filters while still working in "
                "some programs.",
            )
        ]


@dataclass(frozen=True)
class SchemeCheck:
    name: str = "url.scheme"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if url.scheme not in DANGEROUS_SCHEMES:
            return []
        return [
            _finding(
                self.name,
                "dangerous",
                Severity.HIGH,
                f"A {url.scheme}: link",
                f"This is a {url.scheme}: link. Instead of opening a website it runs script or "
                "opens content embedded in the link itself, which a normal link never needs to.",
                url_evidence(url, "scheme", url.scheme),
            )
        ]


@dataclass(frozen=True)
class HostCheck:
    name: str = "url.host"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or not url.host:
            return []
        out: list[Finding] = []
        shown = url.raw_host or url.host
        host_proof = url_evidence(url, "host", shown)

        if url.ip is not None:
            disguised = shown.strip("[]").lower() != str(url.ip)
            out.append(
                _finding(
                    self.name,
                    "ip_literal",
                    Severity.MEDIUM,
                    "Goes to a bare IP address",
                    f"The address goes to {shown}"
                    + (f", which browsers read as the IP address {url.ip}" if disguised else "")
                    + ". Real organisations use domain names; a bare address hides who runs "
                    "the site.",
                    host_proof,
                )
            )
        if "%" in url.raw_host:
            out.append(
                _finding(
                    self.name,
                    "percent_encoded",
                    Severity.MEDIUM,
                    "The site name is disguised with %-codes",
                    f"The site name is written as '{url.raw_host}', which browsers decode to "
                    f"{url.host}. Writing a name in %-codes has no purpose except making it "
                    "unreadable to people and filters.",
                    host_proof,
                )
            )
        if url.domain is None:
            return out

        depth = len([p for p in url.domain.subdomain.split(".") if p])
        if depth > MAX_SUBDOMAIN_LABELS:
            out.append(
                _finding(
                    self.name,
                    "deep_subdomains",
                    Severity.LOW,
                    "Unusually many parts in the site name",
                    f"The site name has {depth} parts in front of the real domain "
                    f"({url.domain.registrable}). Long chains of subdomains are a way to push "
                    "the real domain out of view on small screens.",
                    host_proof,
                )
            )
        if len(url.host) > LONG_HOST:
            out.append(
                _finding(
                    self.name,
                    "long",
                    Severity.LOW,
                    "Very long site name",
                    f"The site name is {len(url.host)} characters long. Very long names hide "
                    "the part that matters.",
                    host_proof,
                )
            )
        label = url.domain.label
        if len(label) >= ENTROPY_MIN_LENGTH and entropy(label) >= ENTROPY_BITS:
            out.append(
                _finding(
                    self.name,
                    "high_entropy",
                    Severity.LOW,
                    "Random-looking domain name",
                    f"The domain name '{label}' looks random ({entropy(label):.1f} bits per "
                    "character). Names generated by software in bulk look like this; names "
                    "people choose usually don't.",
                    url_evidence(url, "host", label),
                )
            )
        shorteners = load_shorteners()
        if url.host.removeprefix("www.") in shorteners or url.domain.registrable in shorteners:
            out.append(
                _finding(
                    self.name,
                    "shortener",
                    Severity.LOW,
                    "A URL shortener",
                    f"{url.host} is a URL shortener, which hides where the link really leads. "
                    "Plenty of genuine links use shorteners, so this is supporting evidence only.",
                    host_proof,
                )
            )
        return out


@dataclass(frozen=True)
class UserinfoCheck:
    name: str = "url.userinfo"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or not url.has_userinfo:
            return []
        before = url.username + (":" + url.password if url.password else "")
        looks_like_site = "." in url.username or bool(brands_in_token_text(url.username))
        return [
            _finding(
                self.name,
                "present",
                Severity.HIGH if looks_like_site else Severity.MEDIUM,
                "Text before @ disguises the real site"
                if looks_like_site
                else "The address contains a username",
                f"The address starts with '{before}@', but everything before the @ is only a "
                f"username: the browser actually goes to {url.host_unicode or url.host}."
                + (" The part before @ is made to look like a website." if looks_like_site else ""),
                url_evidence(url, "userinfo", url.username),
                url_evidence(url, "host", url.raw_host or url.host),
            )
        ]


@dataclass(frozen=True)
class BrandPlacementCheck:
    name: str = "url.brand"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.domain is None:
            return []
        registrable = url.domain.registrable
        out: list[Finding] = []

        for brand in brands_in_token_text(url.domain.subdomain):
            if brand.owns(url.host):
                continue
            out.append(
                _finding(
                    self.name,
                    "in_subdomain",
                    Severity.HIGH,
                    f"Puts {brand.name} in front of someone else's domain",
                    f"The address starts with '{url.domain.subdomain}', which mentions "
                    f"{brand.name}, but the site really belongs to {registrable}. Only the end "
                    "of a site name says who owns it.",
                    url_evidence(url, "host", url.domain.subdomain),
                )
            )
            break

        path = url.path_decoded
        for brand in brands_in_token_text(path):
            if brand.owns(url.host):
                continue
            login = any(word in path.lower() for word in LOGIN_WORDS)
            out.append(
                _finding(
                    self.name,
                    "in_path",
                    Severity.MEDIUM if login else Severity.LOW,
                    f"Mentions {brand.name} on someone else's site",
                    f"The page path mentions {brand.name}"
                    + (" next to a sign-in word" if login else "")
                    + f", but the site is {registrable}, which isn't one of {brand.name}'s.",
                    url_evidence(url, "path", url.path),
                )
            )
            break
        return out


@dataclass(frozen=True)
class TldCheck:
    name: str = "url.tld"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or url.domain is None:
            return []
        tld = url.domain.suffix.rpartition(".")[2]
        if tld not in suspicious_tlds():
            return []
        return [
            _finding(
                self.name,
                "suspicious",
                Severity.LOW,
                f"A .{tld} address",
                f".{tld} is one of the top-level domains most used for phishing, mostly "
                f"because names there are cheap. Most .{tld} sites are legitimate, so this is "
                "supporting evidence only.",
                url_evidence(url, "host", url.host),
            )
        ]


@dataclass(frozen=True)
class PortCheck:
    name: str = "url.port"

    async def run(self, url: ParsedUrl, ctx: CheckContext) -> list[Finding]:
        if not url.valid or not url.explicit_port or url.port in (80, 443):
            return []
        return [
            _finding(
                self.name,
                "non_standard",
                Severity.LOW,
                f"Uses port {url.port}",
                f"The address asks for port {url.port}. Public websites use the standard ports; "
                "an unusual one often means a temporary or hand-run server.",
                url_evidence(url, "port", str(url.port)),
            )
        ]


def lexical_checks() -> tuple[
    ParseCheck,
    SchemeCheck,
    HostCheck,
    UserinfoCheck,
    BrandPlacementCheck,
    TldCheck,
    PortCheck,
]:
    return (
        ParseCheck(),
        SchemeCheck(),
        HostCheck(),
        UserinfoCheck(),
        BrandPlacementCheck(),
        TldCheck(),
        PortCheck(),
    )
