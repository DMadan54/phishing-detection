"""Parse URLs the way a browser does.

Python's urllib and browsers disagree on some URLs, and attackers use the
difference. In "https://evil.example\\@paypal.com/" a browser treats the
backslash as a slash and goes to evil.example, while urllib reads the host as
paypal.com. If we read a URL differently from the victim's browser, we analyse
the wrong site.

So parsing uses ada-url, an implementation of the WHATWG URL Standard (the
one browsers and Node.js follow). It also applies browser normalisation:
percent-decoding and IDNA in hosts, the IPv4 spellings browsers accept
(2130706433 and 0x7f.1 both mean 127.0.0.1), and dropping tabs and newlines.

The original text is kept for evidence. The normalised parts are what the
checks analyse.
"""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote

import ada_url

from phishlens.domains import DomainParts, split_domain
from phishlens.findings import Span

DEFAULT_PORTS = {"http": 80, "https": 443}
SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
MAX_URL_CHARS = 2048

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_HAS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_LOOKS_LIKE_HOST = re.compile(r"^[^\s/:?#@]+\.[^\s/?#]+")


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    original: str  # exactly as given
    valid: bool
    href: str = ""  # normalised by the WHATWG rules
    scheme: str = ""  # "https", without the colon
    username: str = ""
    password: str = ""
    host: str = ""  # ASCII (punycode), lower-case; IPv6 without brackets
    host_unicode: str = ""
    raw_host: str = ""  # the host as written in the original, best effort
    ip: IPAddress | None = None
    port: int | None = None  # explicit port, or the scheme's default
    explicit_port: bool = False
    path: str = ""
    query: str = ""  # without "?"
    fragment: str = ""  # without "#"
    domain: DomainParts | None = None  # None for IPs and URLs without a host
    scheme_added: bool = False  # "paypal.com" was read as "http://paypal.com"

    @property
    def path_decoded(self) -> str:
        return unquote(self.path)

    @property
    def query_decoded(self) -> str:
        return unquote(self.query)

    @property
    def has_userinfo(self) -> bool:
        return bool(self.username or self.password)

    def span_of(self, text: str) -> Span | None:
        """Where text appears in the original URL (ignoring case), if it does."""
        if not text:
            return None
        start = self.original.lower().find(text.lower())
        return Span(start=start, end=start + len(text)) if start >= 0 else None


def _raw_host(text: str, special: bool) -> str:
    """The host part as the sender wrote it, before any normalisation."""
    _, sep, rest = text.partition("://")
    if not sep:
        return ""
    stops = "/?#\\" if special else "/?#"
    end = min((i for i in (rest.find(c) for c in stops) if i >= 0), default=len(rest))
    authority = rest[:end].rpartition("@")[2]
    if authority.startswith("["):
        return authority.partition("]")[0] + "]"
    return authority.rpartition(":")[0] if authority.count(":") == 1 else authority


def parse_url(text: str) -> ParsedUrl:
    """Parse a URL as a browser would. Never raises."""
    original = text
    candidate = text.strip()
    added = False
    if not _HAS_SCHEME.match(candidate) and _LOOKS_LIKE_HOST.match(candidate):
        candidate, added = "http://" + candidate, True
    try:
        parts = ada_url.parse_url(candidate)
    except ValueError:
        return ParsedUrl(original=original, valid=False)

    scheme = parts["protocol"].rstrip(":").lower()
    hostname = parts["hostname"].lower()
    host = hostname.strip("[]")
    ip = _ip(host)
    explicit = bool(parts["port"])
    port = int(parts["port"]) if explicit else DEFAULT_PORTS.get(scheme)
    try:
        host_unicode = ada_url.idna_to_unicode(host) if host and not ip else host
    except Exception:
        host_unicode = host
    return ParsedUrl(
        original=original,
        valid=True,
        href=parts["href"],
        scheme=scheme,
        username=parts["username"],
        password=parts["password"],
        host=host,
        host_unicode=host_unicode,
        raw_host=_raw_host(candidate, scheme in SPECIAL_SCHEMES),
        ip=ip,
        port=port,
        explicit_port=explicit,
        path=parts["pathname"],
        query=parts["search"].removeprefix("?"),
        fragment=parts["hash"].removeprefix("#"),
        domain=split_domain(host) if host and not ip else None,
        scheme_added=added,
    )


def join(base: str, reference: str) -> str | None:
    """Resolve a link or Location header against a base URL, as a browser would."""
    try:
        return str(ada_url.join_url(base, reference.strip()))
    except ValueError:
        return None


def _ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None
