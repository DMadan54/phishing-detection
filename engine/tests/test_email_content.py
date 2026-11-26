"""Link, attachment and language checks."""

import io
import ipaddress
import zipfile

import pytest

from phishlens.email.attachments import AttachmentCheck, OleMacroScanner
from phishlens.email.language import LanguageCheck
from phishlens.email.links import LinkCheck, ip_in_host
from phishlens.email.parse import ParsedEmail, parse_email
from phishlens.findings import Check, Severity
from tests.email_checks import findings_for, ids_for
from tests.email_world import fixture


class FakeMacros:
    """Real olevba can't be given a genuine macro document (see the plan), so
    the positive case uses this; OleMacroScanner is tested on negatives."""

    def has_macros(self, filename: str, content: bytes) -> bool:
        return filename.endswith(".xlsm")


CONTENT_CHECKS: list[Check[ParsedEmail]] = [
    LinkCheck(),
    AttachmentCheck(FakeMacros()),
    LanguageCheck(),
]

EXPECTED: dict[str, set[str]] = {
    "plain_safe": set(),
    "legit_dkim_signed": set(),
    "legit_subdomain_relaxed": set(),
    "link_text_mismatch": {"email.links.text_mismatch"},
    "risky_links": {
        "email.links.ip_host",
        "email.links.shortener",
        "email.links.dangerous_scheme",
    },
    "double_extension": {
        "email.attachments.double_extension",
        "email.attachments.executable",
        "email.attachments.type_mismatch",
    },
    "bidi_and_archive": {
        "email.attachments.bidi_name",
        "email.attachments.executable",
        "email.attachments.archive",
    },
    "html_smuggling": {"email.attachments.html"},
    "type_mismatch": {"email.attachments.type_mismatch"},
    "macro_document": {"email.attachments.macros"},
    "brand_spoof_dmarc_fail": {"email.language.urgency", "email.language.credential_request"},
    "reply_to_hijack": {"email.language.urgency"},
    "malformed": set(),
}

ALL_IDS = {
    "email.links.text_mismatch",
    "email.links.ip_host",
    "email.links.shortener",
    "email.links.dangerous_scheme",
    "email.attachments.executable",
    "email.attachments.double_extension",
    "email.attachments.bidi_name",
    "email.attachments.archive",
    "email.attachments.macros",
    "email.attachments.html",
    "email.attachments.type_mismatch",
    "email.language.urgency",
    "email.language.credential_request",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
async def test_fixture_findings(name: str) -> None:
    assert await ids_for(name, CONTENT_CHECKS) == EXPECTED[name]


def test_every_id_has_a_positive_and_a_negative() -> None:
    for finding_id in ALL_IDS:
        assert any(finding_id in ids for ids in EXPECTED.values()), finding_id
        assert any(finding_id not in ids for ids in EXPECTED.values()), finding_id


# --- links -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("198.51.100.77", "198.51.100.77"),
        ("198.51.100.77.", "198.51.100.77"),
        ("3325256781", "198.51.100.77"),
        ("0xc633644d", "198.51.100.77"),
        ("0306.0063.0144.0115", "198.51.100.77"),
        ("198.51.25677", "198.51.100.77"),
        ("2001:db8::1", "2001:db8::1"),
        ("example.com", None),
        ("1.2.3.4.5", None),
        ("999.1.1.1", None),
        ("08.1.1.1", None),
    ],
)
def test_ip_in_host(host: str, expected: str | None) -> None:
    result = ip_in_host(host)
    assert result == (ipaddress.ip_address(expected) if expected else None)


def html(*anchors: str) -> ParsedEmail:
    body = "".join(anchors)
    return parse_email(
        f"From: a@shop.example\r\nContent-Type: text/html\r\n\r\n<html>{body}</html>".encode()
    )


@pytest.mark.parametrize(
    ("anchor", "expected"),
    [
        ('<a href="https://www.paypal.com/x">paypal.com</a>', set()),
        ('<a href="https://evil.test/">Click here</a>', set()),
        ('<a href="https://click.shop.example/t">www.shop.example</a>', set()),
        ('<a href="mailto:help@shop.example">help@shop.example</a>', set()),
        (
            '<a href="http://198.51.100.1/">https://paypal.com</a>',
            {"email.links.text_mismatch", "email.links.ip_host"},
        ),
        ('<a href="https://paypal.com.evil.test/">paypal.com</a>', {"email.links.text_mismatch"}),
        ('<a href="java\tscript:alert(1)">Open</a>', {"email.links.dangerous_scheme"}),
        ('<a href="https://tinyurl.com/abc">More</a>', {"email.links.shortener"}),
        ('<a href="https://www.bit.ly/abc">More</a>', {"email.links.shortener"}),
        ('<a href="https://notbit.ly/abc">More</a>', set()),
    ],
)
async def test_link_edge_cases(anchor: str, expected: set[str]) -> None:
    assert await ids_for(html(anchor), [LinkCheck()]) == expected


async def test_plain_text_links_are_checked_too() -> None:
    msg = parse_email(b"From: a@shop.example\r\n\r\nGo to http://198.51.100.9/login now\r\n")
    assert await ids_for(msg, [LinkCheck()]) == {"email.links.ip_host"}


# --- attachments -------------------------------------------------------------


def with_attachment(filename: str, content_type: str, data: bytes) -> ParsedEmail:
    import base64

    encoded = base64.b64encode(data).decode()
    raw = (
        "From: a@shop.example\r\n"
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
        f"--b\r\nContent-Type: {content_type}\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
        f"{encoded}\r\n--b--\r\n"
    )
    return parse_email(raw.encode())


def zipped(encrypted: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", b"x")
    data = bytearray(buffer.getvalue())
    if encrypted:
        # zipfile can't write encrypted entries, so set the "encrypted" flag
        # (bit 0 of the general-purpose flags) in the central directory entry.
        central = data.find(bytes.fromhex("504b0102"))  # "PK"
        data[central + 8] |= 0x01
    return bytes(data)


async def test_password_protected_archive_is_more_serious() -> None:
    plain = await findings_for(
        with_attachment("a.zip", "application/zip", zipped()), [AttachmentCheck()]
    )
    locked = await findings_for(
        with_attachment("a.zip", "application/zip", zipped(encrypted=True)), [AttachmentCheck()]
    )
    assert [f.severity for f in plain] == [Severity.LOW]
    assert [f.severity for f in locked] == [Severity.MEDIUM]


async def test_trailing_dot_does_not_hide_an_executable() -> None:
    msg = with_attachment("setup.exe.", "application/octet-stream", b"MZ" + b"\x00" * 60)
    assert await ids_for(msg, [AttachmentCheck()]) == {"email.attachments.executable"}


async def test_office_zip_is_not_a_type_mismatch() -> None:
    msg = with_attachment(
        "notes.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        zipped(),
    )
    assert await ids_for(msg, [AttachmentCheck(FakeMacros())]) == set()


async def test_plain_html_attachment_is_medium() -> None:
    msg = with_attachment("page.html", "text/html", b"<html><body>Hello</body></html>")
    (finding,) = await findings_for(msg, [AttachmentCheck()])
    assert finding.severity is Severity.MEDIUM


async def test_smuggling_markers_are_quoted() -> None:
    (finding,) = await findings_for("html_smuggling", [AttachmentCheck()])
    assert finding.severity is Severity.HIGH
    assert "atob(" in finding.explanation and "new blob(" in finding.explanation


def test_real_olevba_finds_no_macros_in_plain_files() -> None:
    scanner = OleMacroScanner()
    for attachment in fixture("macro_document").attachments:
        assert scanner.has_macros(attachment.filename or "", attachment.content) is False
    assert scanner.has_macros("broken.doc", b"\xd0\xcf\x11\xe0 not really OLE") is False


# --- language ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Your order has shipped and will arrive on Tuesday.", set()),
        (
            "Please verify your account within 48 hours.",
            {"email.language.urgency", "email.language.credential_request"},
        ),
        (
            "Your payment failed. Enter your card details here.",
            {"email.language.urgency", "email.language.credential_request"},
        ),
        ("We have restored service after the outage.", set()),
    ],
)
async def test_language_patterns(text: str, expected: set[str]) -> None:
    msg = parse_email(f"From: a@shop.example\r\n\r\n{text}\r\n".encode())
    assert await ids_for(msg, [LanguageCheck()]) == expected


async def test_language_is_never_more_than_low() -> None:
    for finding in await findings_for("brand_spoof_dmarc_fail", [LanguageCheck()]):
        assert finding.severity is Severity.LOW
        assert "supporting evidence only" in finding.explanation
