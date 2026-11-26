"""Turn a raw email into the facts the checks need.

Parsing uses the standard library's email package with policy.default, which
decodes encoded headers (=?utf-8?...?=), parses address lists and handles
MIME. The raw bytes are kept alongside, because DKIM verifies a signature
over the exact bytes and any re-serialisation would break it.

parse_email never raises. A broken message is evidence, so problems are
recorded in ParsedEmail.defects for the structure check to report, and
whatever could be extracted is still returned.

Evidence offsets for headers (HeaderField.span) index the raw bytes. Email
headers are ASCII, so for them a byte offset is also a character offset.
"""

import email
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Literal

import puremagic

from phishlens.domains import normalise_domain
from phishlens.email.received import ReceivedHop, parse_received
from phishlens.findings import Span

# Caps that stop a hostile message from making parsing arbitrarily slow.
MAX_PARTS = 500
MAX_LINKS = 1000

TEXT_TYPES = ("text/plain", "text/html")


@dataclass(frozen=True, slots=True)
class Address:
    display_name: str
    addr_spec: str
    domain: str | None  # normalised (lower-case, punycode), None if unusable


@dataclass(frozen=True, slots=True)
class HeaderField:
    name: str
    value: str  # decoded, unfolded
    span: Span | None  # where the whole header sits in the raw bytes


@dataclass(frozen=True, slots=True)
class Link:
    href: str
    text: str  # what the reader sees (anchor text, or the URL itself in plain text)
    source: Literal["html", "text"]


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str | None
    declared_type: str  # the Content-Type the sender wrote
    sniffed_type: str | None  # what the bytes actually look like, if recognised
    size: int
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ParsedEmail:
    raw: bytes
    headers: tuple[HeaderField, ...] = ()
    from_addresses: tuple[Address, ...] = ()
    from_header_count: int = 0
    reply_to: tuple[Address, ...] = ()
    sender: Address | None = None
    return_path: str | None = None  # "" for the null sender <>
    received: tuple[ReceivedHop, ...] = ()
    list_id: str | None = None
    message_id: str | None = None
    date: datetime | None = None
    subject: str = ""
    text_bodies: tuple[str, ...] = ()
    html_bodies: tuple[str, ...] = ()
    html_text: tuple[str, ...] = ()  # the visible text of each HTML body
    links: tuple[Link, ...] = ()
    attachments: tuple[Attachment, ...] = ()
    defects: tuple[str, ...] = ()

    @property
    def from_address(self) -> Address | None:
        """The single From address, or None if there isn't exactly one."""
        if self.from_header_count == 1 and len(self.from_addresses) == 1:
            return self.from_addresses[0]
        return None

    def headers_named(self, name: str) -> tuple[HeaderField, ...]:
        name = name.lower()
        return tuple(h for h in self.headers if h.name.lower() == name)

    def header(self, name: str) -> HeaderField | None:
        found = self.headers_named(name)
        return found[0] if found else None

    def readable_text(self) -> str:
        """Subject plus every body as the reader sees it, for language checks."""
        return "\n".join((self.subject, *self.text_bodies, *self.html_text))


def parse_email(raw: bytes) -> ParsedEmail:
    try:
        return _parse(raw)
    except Exception as exc:  # the stdlib parser has edge cases that raise
        return ParsedEmail(raw=raw, defects=(f"UnparseableMessage:{type(exc).__name__}",))


def _parse(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=policy.default)
    defects: list[str] = []

    headers = _headers(msg, raw, defects)
    if not headers:
        defects.append("NoHeaders")

    from_values = msg.get_all("From") or []
    bodies = _Bodies()
    bodies.walk(msg, defects)

    return ParsedEmail(
        raw=raw,
        headers=headers,
        from_addresses=_addresses(from_values, defects),
        from_header_count=len(from_values),
        reply_to=_addresses(msg.get_all("Reply-To") or [], defects),
        sender=next(iter(_addresses(msg.get_all("Sender") or [], defects)), None),
        return_path=_return_path(msg),
        received=tuple(
            parse_received(h.value, i)
            for i, h in enumerate(h for h in headers if h.name.lower() == "received")
        ),
        list_id=_first_value(headers, "list-id"),
        message_id=_message_id(headers),
        date=_date(msg),
        subject=_first_value(headers, "subject") or "",
        text_bodies=tuple(bodies.text),
        html_bodies=tuple(bodies.html),
        html_text=tuple(bodies.html_text),
        links=tuple(bodies.links[:MAX_LINKS]),
        attachments=tuple(bodies.attachments),
        defects=tuple(defects),
    )


# --- headers -----------------------------------------------------------------


def _header_spans(raw: bytes) -> Iterator[tuple[str, Span]]:
    """Where each header sits in the raw bytes, following folded lines."""
    ends = [i for i in (raw.find(b"\r\n\r\n"), raw.find(b"\n\n")) if i >= 0]
    block = raw[: min(ends)] if ends else raw
    current: tuple[str, int, int] | None = None
    for line in re.finditer(rb"[^\r\n]*", block):
        if not line.group():
            continue
        start, end = line.span()
        if line.group()[:1] in (b" ", b"\t") and current:
            current = (current[0], current[1], end)
            continue
        if current:
            yield current[0], Span(start=current[1], end=current[2])
        name, colon, _ = line.group().partition(b":")
        current = (name.decode("latin-1").strip().lower(), start, end) if colon else None
    if current:
        yield current[0], Span(start=current[1], end=current[2])


def _headers(msg: EmailMessage, raw: bytes, defects: list[str]) -> tuple[HeaderField, ...]:
    spans: dict[str, list[Span]] = {}
    for name, where in _header_spans(raw):
        spans.setdefault(name, []).append(where)

    fields: list[HeaderField] = []
    seen: dict[str, int] = {}
    for name, raw_value in msg.raw_items():
        key = name.lower()
        index = seen.get(key, 0)
        seen[key] = index + 1
        try:
            parsed = msg.policy.header_fetch_parse(name, raw_value)
            value = str(parsed)
            defects.extend(type(d).__name__ for d in getattr(parsed, "defects", ()))
        except Exception:
            value = str(raw_value)
            defects.append(f"HeaderParseError:{name}")
        candidates = spans.get(key, [])
        span = candidates[index] if index < len(candidates) else None
        fields.append(HeaderField(name=name, value=" ".join(value.split()), span=span))
    return tuple(fields)


def _addresses(values: list[object], defects: list[str]) -> tuple[Address, ...]:
    found: list[Address] = []
    for value in values:
        try:
            addresses = getattr(value, "addresses", ())
        except Exception:
            defects.append("AddressParseError")
            continue
        for a in addresses:
            domain = normalise_domain(a.domain) if a.domain else None
            found.append(Address(a.display_name or "", a.addr_spec or "", domain))
    return tuple(found)


def _first_value(headers: tuple[HeaderField, ...], name: str) -> str | None:
    return next((h.value for h in headers if h.name.lower() == name), None)


def _return_path(msg: EmailMessage) -> str | None:
    value = msg.get("Return-Path")
    if value is None:
        return None
    text = str(value).strip()
    if text in ("<>", ""):
        return ""
    return parseaddr(text)[1] or text.strip("<>")


def _message_id(headers: tuple[HeaderField, ...]) -> str | None:
    value = _first_value(headers, "message-id")
    return value.strip().strip("<>").strip() if value else None


def _date(msg: EmailMessage) -> datetime | None:
    try:
        header = msg.get("Date")
        value = getattr(header, "datetime", None)
    except Exception:
        return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# --- bodies, links and attachments -------------------------------------------

_TEXT_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'()\[\]]+", re.IGNORECASE)


class _Bodies:
    def __init__(self) -> None:
        self.text: list[str] = []
        self.html: list[str] = []
        self.html_text: list[str] = []
        self.links: list[Link] = []
        self.attachments: list[Attachment] = []

    def walk(self, msg: EmailMessage, defects: list[str]) -> None:
        for count, part in enumerate(msg.walk(), start=1):
            if count > MAX_PARTS:
                defects.append("TooManyParts")
                break
            defects.extend(type(d).__name__ for d in part.defects)
            if part.is_multipart():
                continue
            self._part(part, defects)

    def _part(self, part: EmailMessage, defects: list[str]) -> None:
        content_type = part.get_content_type()
        filename = _safely(part.get_filename, defects)
        is_body = (
            content_type in TEXT_TYPES
            and filename is None
            and part.get_content_disposition() != "attachment"
        )
        if not is_body:
            content = part.get_payload(decode=True)
            data = content if isinstance(content, bytes) else b""
            self.attachments.append(
                Attachment(filename, content_type, _sniff(data), len(data), data)
            )
            return

        text = _text_content(part, defects)
        if content_type == "text/plain":
            self.text.append(text)
            self.links.extend(Link(href=u, text=u, source="text") for u in _urls_in_text(text))
        else:
            self.html.append(text)
            scan = _HtmlScan()
            try:
                scan.feed(text)
                scan.close()
            except Exception:
                defects.append("HtmlParseError")
            self.html_text.append(" ".join(" ".join(scan.text).split()))
            self.links.extend(scan.links)


def _safely(get: Callable[[], str | None], defects: list[str]) -> str | None:
    try:
        return get()
    except Exception:
        defects.append("FilenameParseError")
        return None


def _text_content(part: EmailMessage, defects: list[str]) -> str:
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except Exception:
        defects.append("UndecodableText")
    payload = part.get_payload(decode=True)
    return payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""


def _urls_in_text(text: str) -> list[str]:
    return [m.group().rstrip(".,;:!?") for m in _TEXT_URL.finditer(text)]


def _sniff(data: bytes) -> str | None:
    if not data:
        return None
    try:
        return puremagic.from_string(data, mime=True) or None
    except (puremagic.PureError, ValueError):
        return None


class _HtmlScan(HTMLParser):
    """Collects links (href plus the text the reader sees) and visible text."""

    _INVISIBLE = frozenset({"script", "style", "noscript", "template", "head"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in self._INVISIBLE:
            self._hidden += 1
        elif tag == "a":
            self._close_anchor()
            href = attributes.get("href")
            if href is not None:
                self._href = href.strip()
                self._anchor = []
        elif tag == "area" and attributes.get("href") is not None:
            alt = attributes.get("alt") or ""
            self.links.append(Link(str(attributes["href"]).strip(), alt, "html"))
        elif tag == "img" and self._href is not None:
            # A linked image: its alt text is what the reader is told.
            self._anchor.append(attributes.get("alt") or "")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._INVISIBLE:
            self._hidden = max(0, self._hidden - 1)
        elif tag == "a":
            self._close_anchor()

    def handle_data(self, data: str) -> None:
        if self._hidden:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)

    def close(self) -> None:
        super().close()
        self._close_anchor()

    def _close_anchor(self) -> None:
        if self._href is not None:
            text = " ".join(" ".join(self._anchor).split())
            self.links.append(Link(self._href, text, "html"))
        self._href = None
        self._anchor = []
