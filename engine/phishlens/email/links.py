"""Links in the message body.

- Text that shows one domain while the link goes to another is the oldest
  phishing trick there is: you read "www.paypal.com", you land on
  evil.example.
- A link to a bare IP address skips the domain system entirely, so there's
  no name to recognise and nothing registered to anyone. Browsers also
  accept odd spellings of IPs, such as http://3325256781/ (one decimal
  number), which hide that it's an IP at all.
- Shorteners hide the destination (supporting evidence only).
- javascript:, data:, vbscript: and file: links run code or open content
  directly instead of going to a website.

Only the URL text is examined here; nothing is ever fetched.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from phishlens.brands import load_shorteners
from phishlens.domains import as_ip, normalise_domain, same_owner
from phishlens.email.parse import Link, ParsedEmail
from phishlens.findings import BodyEvidence, CheckContext, Finding, Severity, UrlEvidence

MAX_EXAMPLES = 5
DANGEROUS_SCHEMES = frozenset({"javascript", "data", "vbscript", "file"})

# Link text that is, as a whole, a URL or a bare domain.
_DOMAIN_TEXT = re.compile(
    r"^(?:https?://)?(?P<host>(?:[a-z0-9-]+\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+))\.?(?:[/:?#]\S*)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Url:
    link: Link
    parts: SplitResult | None
    scheme: str
    host: str | None


def _clean(href: str) -> str:
    """Strip what browsers ignore: surrounding whitespace and control
    characters, and tabs or newlines anywhere ("java\tscript:" still runs)."""
    return re.sub(r"[\t\r\n]", "", href).strip("\x00\x01\x02\x03\x04\x05\x06\x07\x08 \x0b\x0c")


def _parse(link: Link) -> _Url:
    href = _clean(link.href)
    if href.lower().startswith("www."):
        href = "http://" + href
    try:
        parts = urlsplit(href)
        host = parts.hostname
    except ValueError:
        return _Url(link, None, "", None)
    return _Url(link, parts, parts.scheme.lower(), host.rstrip(".") if host else None)


def ip_in_host(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP a host names, including the forms browsers accept for IPv4:
    a single number (3325256781), hex (0xc6336457) and octal parts (0306.0063...)."""
    direct = as_ip(host)
    if direct:
        return direct
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts.pop()
    if not 1 <= len(parts) <= 4:
        return None
    numbers = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                numbers.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                numbers.append(int(part, 8))
            else:
                numbers.append(int(part, 10))
        except ValueError:
            return None
    *leading, last = numbers
    if any(n > 255 for n in leading) or last >= 256 ** (5 - len(numbers)):
        return None
    value = last
    for i, n in enumerate(leading):
        value += n << (8 * (3 - i))
    return ipaddress.IPv4Address(value)


@dataclass(frozen=True)
class LinkCheck:
    name: str = "email.links"

    async def run(self, msg: ParsedEmail, ctx: CheckContext) -> list[Finding]:
        urls = [_parse(link) for link in msg.links]
        findings = [
            *self._text_mismatch(urls),
            *self._ip_hosts(urls),
            *self._shorteners(urls),
            *self._dangerous(urls),
        ]
        return findings

    def _text_mismatch(self, urls: list[_Url]) -> list[Finding]:
        examples: list[tuple[str, str]] = []
        for url in urls:
            if url.link.source != "html" or not url.host:
                continue
            match = _DOMAIN_TEXT.match(url.link.text.strip())
            if not match:
                continue
            shown = normalise_domain(match.group("host"))
            real = normalise_domain(url.host) or url.host
            if shown and not same_owner(shown, real):
                examples.append((url.link.text.strip(), real))
        if not examples:
            return []
        shown, real = examples[0]
        return [
            self._finding(
                "text_mismatch",
                Severity.HIGH,
                "A link shows one address but goes to another",
                f"A link reads '{shown}' but actually goes to {real}. Showing a trusted "
                "address while linking somewhere else is a classic phishing trick."
                + self._more(len(examples)),
                tuple(
                    e
                    for text, host in examples[:MAX_EXAMPLES]
                    for e in (BodyEvidence(excerpt=text), UrlEvidence(component="host", value=host))
                ),
            )
        ]

    def _ip_hosts(self, urls: list[_Url]) -> list[Finding]:
        examples = [(u, ip) for u in urls if u.host for ip in [ip_in_host(u.host)] if ip]
        if not examples:
            return []
        url, ip = examples[0]
        disguised = url.host != str(ip)
        return [
            self._finding(
                "ip_host",
                Severity.MEDIUM,
                "A link goes to a bare IP address",
                f"A link goes to {url.host}"
                + (f" (which browsers read as the IP address {ip})" if disguised else "")
                + ". Real organisations link to their domain names; a bare address hides who "
                "runs the site." + self._more(len(examples)),
                tuple(
                    UrlEvidence(component="host", value=u.host or "")
                    for u, _ in examples[:MAX_EXAMPLES]
                ),
            )
        ]

    def _shorteners(self, urls: list[_Url]) -> list[Finding]:
        shorteners = load_shorteners()
        examples = [u for u in urls if u.host and u.host.removeprefix("www.") in shorteners]
        if not examples:
            return []
        return [
            self._finding(
                "shortener",
                Severity.LOW,
                "A link uses a URL shortener",
                f"A link goes through {examples[0].host}, a URL shortener, which hides where "
                "it really leads. Plenty of genuine mail uses shorteners, so this is supporting "
                "evidence only." + self._more(len(examples)),
                tuple(
                    UrlEvidence(component="host", value=u.host or "")
                    for u in examples[:MAX_EXAMPLES]
                ),
            )
        ]

    def _dangerous(self, urls: list[_Url]) -> list[Finding]:
        examples = [u for u in urls if u.scheme in DANGEROUS_SCHEMES]
        if not examples:
            return []
        schemes = ", ".join(dict.fromkeys(f"{u.scheme}:" for u in examples))
        return [
            self._finding(
                "dangerous_scheme",
                Severity.HIGH,
                "A link runs code or opens content directly",
                f"The message contains {schemes} links. Instead of opening a website, these run "
                "script or open content embedded in the link itself, which legitimate email "
                "has no reason to do." + self._more(len(examples)),
                tuple(
                    UrlEvidence(component="scheme", value=u.scheme) for u in examples[:MAX_EXAMPLES]
                ),
            )
        ]

    @staticmethod
    def _more(count: int) -> str:
        return f" ({count} such links in total.)" if count > 1 else ""

    def _finding(
        self,
        what: str,
        severity: Severity,
        title: str,
        explanation: str,
        proof: tuple[BodyEvidence | UrlEvidence, ...],
    ) -> Finding:
        return Finding(
            id=f"{self.name}.{what}",
            check=self.name,
            severity=severity,
            title=title,
            explanation=explanation,
            evidence=proof,
        )
