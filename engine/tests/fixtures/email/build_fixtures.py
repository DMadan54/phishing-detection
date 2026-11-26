"""Build every email fixture in this folder.

    uv run python -m tests.fixtures.email.build_fixtures      (from engine/)

Every fixture is hand-made here, so each one is explained by the code that
makes it. Anything that isn't the brand being impersonated uses reserved
names (.example, .test) and documentation IP ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24). Attachments are fake: the "executable" is
an MZ header and some text, and the HTML-smuggling page "downloads" a text
file that says it is harmless.

Signatures use the throwaway key in keys/, whose public half the tests serve
from fake DNS (tests/email_world.py). Signing time is pinned, so running the
script twice gives identical bytes; test_fixtures.py checks that the files
on disk match what this script builds.

The key was made once with the `cryptography` package (RSA, 2048 bits); see
the commit that added it.
"""

import base64
import io
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from unittest import mock

import dkim

HERE = Path(__file__).parent
PRIVATE_KEY = (HERE / "keys" / "dkim-test-private.pem").read_bytes()

CRLF = b"\r\n"
SIGN_TIME = 1767607200  # Mon, 05 Jan 2026 10:00:00 UTC
DATE = "Mon, 05 Jan 2026 10:00:00 +0000"
RECEIVED_AT = "Mon, 05 Jan 2026 10:00:05 +0000"
RECIPIENT = "you@recipient.example"
SIGNED_HEADERS = [b"from", b"to", b"subject", b"date", b"message-id", b"content-type"]

Headers = Sequence[tuple[str, str]]


# --- building blocks ---------------------------------------------------------


def message(headers: Headers, body: bytes) -> bytes:
    lines = b"".join(f"{name}: {value}".encode() + CRLF for name, value in headers)
    return lines + CRLF + body


def text_body(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode()


def multipart(boundary: str, parts: Sequence[bytes]) -> bytes:
    out = b"".join(b"--" + boundary.encode() + CRLF + part + CRLF for part in parts)
    return out + b"--" + boundary.encode() + b"--" + CRLF


def part(content_type: str, body: bytes, *extra: tuple[str, str]) -> bytes:
    return message([("Content-Type", content_type), *extra], body)


def attachment(filename_param: str, content_type: str, data: bytes) -> bytes:
    encoded = base64.encodebytes(data).replace(b"\n", CRLF)
    return message(
        [
            ("Content-Type", content_type),
            ("Content-Disposition", f"attachment; {filename_param}"),
            ("Content-Transfer-Encoding", "base64"),
        ],
        encoded,
    )


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 5, 10, 0, 0))
            archive.writestr(info, data)
    return buffer.getvalue()


def dkim_sign(raw: bytes, domain: str) -> bytes:
    with mock.patch("time.time", return_value=float(SIGN_TIME)):
        signature: bytes = dkim.sign(
            raw,
            b"s1",
            domain.encode(),
            PRIVATE_KEY,
            include_headers=SIGNED_HEADERS,
            canonicalize=(b"relaxed", b"simple"),
        )
    return signature + raw


def arc_seal(raw: bytes, domain: str) -> bytes:
    headers: list[bytes] = dkim.arc_sign(
        raw, b"s1", domain.encode(), PRIVATE_KEY, domain.encode(), timestamp=SIGN_TIME + 60
    )
    return b"".join(headers) + raw


def received(helo: str, ip: str, by: str = "mx.recipient.example", at: str = RECEIVED_AT) -> str:
    return f"from {helo} ({helo} [{ip}])\r\n\tby {by} with ESMTPS id 4kTx9;\r\n\t{at}"


def prepend(raw: bytes, headers: Headers) -> bytes:
    """Add header lines above the existing ones, as each server on the way does."""
    return b"".join(f"{name}: {value}".encode() + CRLF for name, value in headers) + raw


def delivered(
    raw: bytes,
    *,
    return_path: str,
    helo: str,
    ip: str,
    at: str = RECEIVED_AT,
    extra_top: Headers = (),
) -> bytes:
    """Add what the recipient's server writes on arrival, on top."""
    trace = [
        *extra_top,
        ("Return-Path", f"<{return_path}>"),
        ("Received", received(helo, ip, at=at)),
    ]
    return prepend(raw, trace)


def basic_headers(
    sender: str, subject: str, message_id: str | None, date: str = DATE
) -> list[tuple[str, str]]:
    headers = [("From", sender), ("To", RECIPIENT), ("Subject", subject), ("Date", date)]
    if message_id:
        headers.append(("Message-ID", f"<{message_id}>"))
    headers.append(("MIME-Version", "1.0"))
    return headers


# --- fixtures ----------------------------------------------------------------


def plain_safe() -> bytes:
    """A colleague's plain-text note. SPF passes and aligns; no DKIM."""
    raw = message(
        [
            *basic_headers(
                "Alice Example <alice@company.example>", "Lunch tomorrow?", "1@company.example"
            ),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("Hi,\nAre you free for lunch tomorrow at 12?\nAlice\n"),
    )
    return delivered(
        raw, return_path="alice@company.example", helo="mail.company.example", ip="192.0.2.50"
    )


def _shop_newsletter(subject: str, html: str) -> bytes:
    return message(
        [
            *basic_headers("Example Shop <news@shop.example>", subject, "n-1001@shop.example"),
            ("Reply-To", "help@shop.example"),
            ("List-Unsubscribe", "<https://shop.example/unsubscribe>"),
            ("Content-Type", 'multipart/alternative; boundary="alt"'),
        ],
        multipart(
            "alt",
            [
                part(
                    "text/plain; charset=utf-8",
                    text_body("Our January offers: https://shop.example/offers\n"),
                ),
                part("text/html; charset=utf-8", text_body(html)),
            ],
        ),
    )


NEWSLETTER_HTML = (
    "<html><body><h1>January offers</h1>\n"
    '<p>See <a href="https://shop.example/offers">our offers</a> or visit\n'
    '<a href="https://www.shop.example/">www.shop.example</a>.</p>\n'
    "</body></html>\n"
)


def legit_dkim_signed() -> bytes:
    """A real-looking newsletter: DKIM-signed by the From domain, SPF passes
    for a subdomain bounce address (relaxed alignment), and the recipient's
    own server added a genuine Authentication-Results header on top."""
    raw = dkim_sign(_shop_newsletter("January offers", NEWSLETTER_HTML), "shop.example")
    return delivered(
        raw,
        return_path="bounce@mail.shop.example",
        helo="mta.shop.example",
        ip="192.0.2.10",
        extra_top=[
            (
                "Authentication-Results",
                "mx.recipient.example; dkim=pass header.d=shop.example; "
                "spf=pass smtp.mailfrom=mail.shop.example; dmarc=pass header.from=shop.example",
            )
        ],
    )


def legit_subdomain_relaxed() -> bytes:
    """Every identity is a different subdomain of shop.example. Relaxed
    alignment and the organisational-domain comparisons must accept it."""
    raw = message(
        [
            *basic_headers(
                "Example Shop Orders <orders@shop.example>",
                "Your order has shipped",
                "o-77@mta.shop.example",
            ),
            ("Reply-To", "support@help.shop.example"),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("Your order 77 has shipped. Track it at https://track.shop.example/77\n"),
    )
    return delivered(
        dkim_sign(raw, "mail.shop.example"),
        return_path="bounce@em.mail.shop.example",
        helo="mta.shop.example",
        ip="192.0.2.11",
    )


def esp_signed() -> bytes:
    """Sent through an email service that signs with its own domain only.
    DKIM is valid but for esp.example; DMARC still passes through SPF."""
    raw = dkim_sign(_shop_newsletter("February offers", NEWSLETTER_HTML), "esp.example")
    return delivered(
        raw, return_path="bounce@mail.shop.example", helo="out.esp.example", ip="192.0.2.12"
    )


def tampered_signed() -> bytes:
    """Signed by shop.example, then the body was changed in transit."""
    raw = dkim_sign(_shop_newsletter("January offers", NEWSLETTER_HTML), "shop.example")
    raw = raw.replace(b"January offers</h1>", b"January offers - now 90% off!</h1>")
    return delivered(
        raw, return_path="bounce@mail.shop.example", helo="mta.shop.example", ip="192.0.2.10"
    )


def brand_spoof_dmarc_fail() -> bytes:
    """Claims to be PayPal. SPF and DKIM both pass, but for evil.test, which
    is exactly what DMARC alignment exists to catch."""
    raw = message(
        [
            *basic_headers(
                '"PayPal" <service@paypal.com>', "Your account has been suspended", "x9@evil.test"
            ),
            ("Content-Type", "text/html; charset=utf-8"),
        ],
        text_body(
            "<html><body><p>Dear customer,</p>\n"
            "<p>Your account has been suspended because of unusual activity.\n"
            "Please verify within 24 hours and confirm your password, or your\n"
            "account will be closed.</p>\n"
            '<p><a href="https://login.evil.test/paypal">Restore access</a></p>\n'
            "</body></html>\n"
        ),
    )
    return delivered(
        dkim_sign(raw, "evil.test"),
        return_path="bounce@evil.test",
        helo="mail.evil.test",
        ip="203.0.113.5",
    )


def lookalike_sender() -> bytes:
    """paypa1.test (a "1" for the "l") passes SPF, DKIM and DMARC for itself.
    Authentication proves who sent it, not that they're who they look like."""
    raw = message(
        [
            *basic_headers(
                "PayPal Support <support@paypa1.test>", "Security notice", "s1@paypa1.test"
            ),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("We noticed a new sign-in. Review it at https://paypa1.test/review\n"),
    )
    return delivered(
        dkim_sign(raw, "paypa1.test"),
        return_path="bounce@paypa1.test",
        helo="mail.paypa1.test",
        ip="203.0.113.20",
    )


def display_name_spoof() -> bytes:
    """The display name is an address (PayPal's); the real one is not.
    random.test publishes no SPF and no DMARC, and the Message-ID comes from
    an unrelated bulk-mail host."""
    raw = message(
        [
            *basic_headers(
                '"service@paypal.com" <billing@random.test>', "Invoice", "7f3a9c@bulk-mailer.test"
            ),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("Please find your invoice details below.\n"),
    )
    return delivered(
        raw, return_path="billing@random.test", helo="mail.random.test", ip="203.0.113.30"
    )


def reply_to_hijack() -> bytes:
    """Business email compromise: looks like the CEO, sent from an attacker's
    server (SPF fails, DMARC fails), and replies go to a freemail account."""
    raw = message(
        [
            *basic_headers(
                "Jane Smith <ceo@company.example>",
                "Urgent: wire transfer today",
                "w1@company.example",
            ),
            ("Reply-To", "jane.smith.ceo@freemail.test"),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body(
            "I need you to process an urgent payment today. Reply with confirmation.\nJane\n"
        ),
    )
    return delivered(
        raw, return_path="ceo@company.example", helo="mail.evil.test", ip="203.0.113.40"
    )


def forged_auth_results() -> bytes:
    """The attacker wrote their own Authentication-Results header claiming
    everything passed for paypal.com. Nothing was signed."""
    raw = message(
        [
            (
                "Authentication-Results",
                "mx.google.com; dkim=pass header.d=paypal.com; "
                "spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com",
            ),
            *basic_headers("PayPal <service@paypal.com>", "Payment received", "p1@paypal.com"),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("You received a payment. Log in to view it.\n"),
    )
    return delivered(raw, return_path="bounce@evil.test", helo="mail.evil.test", ip="203.0.113.5")


def link_text_mismatch() -> bytes:
    """A link that shows www.paypal.com but goes to evil.test, next to two
    honest links (same URL, and a tracking subdomain of the same owner)."""
    raw = message(
        [
            *basic_headers("Example Shop <news@shop.example>", "Account update", "l1@shop.example"),
            ("Content-Type", "text/html; charset=utf-8"),
        ],
        text_body(
            "<html><body>\n"
            '<p><a href="https://evil.test/signin">www.paypal.com</a></p>\n'
            '<p><a href="https://shop.example/a">https://shop.example/a</a></p>\n'
            '<p><a href="https://click.shop.example/t?u=1">shop.example</a></p>\n'
            "</body></html>\n"
        ),
    )
    return delivered(
        dkim_sign(raw, "shop.example"),
        return_path="bounce@mail.shop.example",
        helo="mta.shop.example",
        ip="192.0.2.10",
    )


def risky_links() -> bytes:
    raw = message(
        [
            *basic_headers("Example Shop <news@shop.example>", "Links", "r1@shop.example"),
            ("Content-Type", "text/html; charset=utf-8"),
        ],
        text_body(
            "<html><body>\n"
            '<a href="http://198.51.100.77/login">Sign in</a>\n'
            '<a href="http://3325256781/login">Sign in again</a>\n'
            '<a href="https://bit.ly/3xYzAbc">Short link</a>\n'
            '<a href="javascript:alert(1)">Open</a>\n'
            '<a href="data:text/html;base64,PGgxPkhlbGxvPC9oMT4=">Preview</a>\n'
            '<a href="https://shop.example/help">Help</a>\n'
            "</body></html>\n"
        ),
    )
    return delivered(
        dkim_sign(raw, "shop.example"),
        return_path="bounce@mail.shop.example",
        helo="mta.shop.example",
        ip="192.0.2.10",
    )


FAKE_EXE = b"MZ" + b"\x00" * 62 + b"PhishLens test fixture. Not a real program.\r\n"


def double_extension() -> bytes:
    raw = message(
        [
            *basic_headers("Accounts <accounts@random.test>", "Invoice 4471", "d1@random.test"),
            ("Content-Type", 'multipart/mixed; boundary="mix"'),
        ],
        multipart(
            "mix",
            [
                part("text/plain; charset=utf-8", text_body("Invoice attached.\n")),
                attachment('filename="invoice.pdf.exe"', "application/pdf", FAKE_EXE),
            ],
        ),
    )
    return delivered(
        raw, return_path="accounts@random.test", helo="mail.random.test", ip="203.0.113.30"
    )


SMUGGLING_PAGE = (
    b"<html><body><p>Loading your remittance advice...</p>\n"
    b"<script>\n"
    b'var data = atob("SGVsbG8sIHRoaXMgaXMgYSBoYXJtbGVzcyBQaGlzaExlbnMgdGVzdCBmaWxlLg==");\n'
    b'var blob = new Blob([data], {type: "application/octet-stream"});\n'
    b'var a = document.createElement("a");\n'
    b"a.href = URL.createObjectURL(blob);\n"
    b'a.download = "remittance.txt";\n'
    b"a.click();\n"
    b"</script></body></html>\n"
)


def html_smuggling() -> bytes:
    """An HTML attachment that builds a file in the browser and "downloads"
    it, so the file never crosses the mail filter as an attachment. The
    payload here is a harmless sentence."""
    raw = message(
        [
            *basic_headers(
                "Payments <payments@random.test>", "Remittance advice", "h1@random.test"
            ),
            ("Content-Type", 'multipart/mixed; boundary="mix"'),
        ],
        multipart(
            "mix",
            [
                part("text/plain; charset=utf-8", text_body("Open the attached remittance.\n")),
                attachment('filename="remittance.html"', "text/html", SMUGGLING_PAGE),
            ],
        ),
    )
    return delivered(
        raw, return_path="payments@random.test", helo="mail.random.test", ip="203.0.113.30"
    )


def bidi_and_archive() -> bytes:
    """invoice<RLO>fdp.exe displays as "invoiceexe.pdf"; plus a zip."""
    raw = message(
        [
            *basic_headers("Accounts <accounts@random.test>", "Documents", "b1@random.test"),
            ("Content-Type", 'multipart/mixed; boundary="mix"'),
        ],
        multipart(
            "mix",
            [
                part("text/plain; charset=utf-8", text_body("Two files attached.\n")),
                attachment(
                    "filename*=utf-8''invoice%E2%80%AEfdp.exe", "application/octet-stream", FAKE_EXE
                ),
                attachment(
                    'filename="documents.zip"',
                    "application/zip",
                    zip_bytes({"readme.txt": b"test\n"}),
                ),
            ],
        ),
    )
    return delivered(
        raw, return_path="accounts@random.test", helo="mail.random.test", ip="203.0.113.30"
    )


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17


def type_mismatch() -> bytes:
    """report.pdf is really a zip; photo.png really is a PNG."""
    raw = message(
        [
            *basic_headers("Example Shop <news@shop.example>", "Your report", "t1@shop.example"),
            ("Content-Type", 'multipart/mixed; boundary="mix"'),
        ],
        multipart(
            "mix",
            [
                part("text/plain; charset=utf-8", text_body("Report and photo attached.\n")),
                attachment('filename="report.pdf"', "application/pdf", zip_bytes({"a.txt": b"x"})),
                attachment('filename="photo.png"', "image/png", PNG),
            ],
        ),
    )
    return delivered(
        dkim_sign(raw, "shop.example"),
        return_path="bounce@mail.shop.example",
        helo="mta.shop.example",
        ip="192.0.2.10",
    )


def macro_document() -> bytes:
    """budget.xlsm is macro-enabled; notes.docx is a plain document."""
    xlsm = zip_bytes(
        {
            "[Content_Types].xml": b"<Types/>",
            "xl/workbook.xml": b"<workbook/>",
            "xl/vbaProject.bin": b"not real VBA",
        }
    )
    docx = zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<document/>"})
    raw = message(
        [
            *basic_headers("Finance <finance@company.example>", "Budget", "m1@company.example"),
            ("Content-Type", 'multipart/mixed; boundary="mix"'),
        ],
        multipart(
            "mix",
            [
                part("text/plain; charset=utf-8", text_body("Budget and notes attached.\n")),
                attachment(
                    'filename="budget.xlsm"', "application/vnd.ms-excel.sheet.macroEnabled.12", xlsm
                ),
                attachment(
                    'filename="notes.docx"',
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    docx,
                ),
            ],
        ),
    )
    return delivered(
        raw, return_path="finance@company.example", helo="mail.company.example", ip="192.0.2.50"
    )


def mailing_list_forwarded() -> bytes:
    """A shop.example post (p=reject) relayed by a mailing list. The list
    tags the subject and adds a footer, which breaks the original DKIM
    signature, and resends from its own server, so SPF is for lists.example.
    The list records what it saw in an ARC seal and signs with its own key."""
    original = dkim_sign(
        message(
            [
                *basic_headers(
                    "Example Shop <news@shop.example>", "Spring meetup", "ml-5@shop.example"
                ),
                ("Content-Type", "text/plain; charset=utf-8"),
            ],
            text_body("Join us for the spring meetup on 12 March.\n"),
        ),
        "shop.example",
    )
    relayed = original.replace(b"Subject: Spring meetup", b"Subject: [shop-fans] Spring meetup")
    relayed += text_body("--\nshop-fans mailing list: https://lists.example/shop-fans\n")
    relayed = prepend(
        relayed,
        [
            (
                "Authentication-Results",
                "lists.example; dkim=pass header.d=shop.example; "
                "spf=pass smtp.mailfrom=mail.shop.example; dmarc=pass header.from=shop.example",
            ),
            ("Received", received("mta.shop.example", "192.0.2.10", by="lists.example", at=DATE)),
            ("List-Id", "Shop fans <shop-fans.lists.example>"),
            ("Reply-To", "shop-fans@lists.example"),
        ],
    )
    relayed = dkim_sign(relayed, "lists.example")
    relayed = arc_seal(relayed, "lists.example")
    return delivered(
        relayed,
        return_path="shop-fans-bounces@lists.example",
        helo="mail.lists.example",
        ip="198.51.100.20",
    )


def malformed() -> bytes:
    """Two From headers, a bad date, broken base64, an unterminated MIME
    boundary, an unclosed link, NUL bytes and a header line with no colon.
    No Received header, so there is no sending IP."""
    return (
        b"From: a@company.example\r\n"
        b"From: b@other.example\r\n"
        b"Date: not a date\r\n"
        b'Content-Type: multipart/mixed; boundary="zz"\r\n'
        b"Subject broken header without a colon\r\n"
        b"\r\n"
        b"--zz\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"!!!not base64!!!\r\n"
        b"--zz\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b'<a href="https://evil.test/">click\x00\x00\r\n'
    )


def date_future() -> bytes:
    raw = message(
        [
            *basic_headers(
                "Alice Example <alice@company.example>",
                "Meeting",
                "f1@company.example",
                date="Mon, 01 Mar 2027 09:00:00 +0000",
            ),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("See you then.\n"),
    )
    return delivered(
        raw, return_path="alice@company.example", helo="mail.company.example", ip="192.0.2.50"
    )


def date_stale() -> bytes:
    """Dated three months before it arrived, and no Message-ID."""
    raw = message(
        [
            *basic_headers(
                "Alice Example <alice@company.example>",
                "Old news",
                None,
                date="Wed, 01 Oct 2025 09:00:00 +0000",
            ),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("Catching up.\n"),
    )
    return delivered(
        raw, return_path="alice@company.example", helo="mail.company.example", ip="192.0.2.50"
    )


def spf_softfail() -> bytes:
    raw = message(
        [
            *basic_headers("Updates <updates@softfail.example>", "Update", "u1@softfail.example"),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("An update.\n"),
    )
    return delivered(
        raw, return_path="updates@softfail.example", helo="mail.softfail.example", ip="203.0.113.60"
    )


def spf_permerror() -> bytes:
    raw = message(
        [
            *basic_headers("Updates <updates@permerror.example>", "Update", "u2@permerror.example"),
            ("Content-Type", "text/plain; charset=utf-8"),
        ],
        text_body("An update.\n"),
    )
    return delivered(
        raw,
        return_path="updates@permerror.example",
        helo="mail.permerror.example",
        ip="203.0.113.61",
    )


FIXTURES: dict[str, Callable[[], bytes]] = {
    "plain_safe": plain_safe,
    "legit_dkim_signed": legit_dkim_signed,
    "legit_subdomain_relaxed": legit_subdomain_relaxed,
    "esp_signed": esp_signed,
    "tampered_signed": tampered_signed,
    "brand_spoof_dmarc_fail": brand_spoof_dmarc_fail,
    "lookalike_sender": lookalike_sender,
    "display_name_spoof": display_name_spoof,
    "reply_to_hijack": reply_to_hijack,
    "forged_auth_results": forged_auth_results,
    "link_text_mismatch": link_text_mismatch,
    "risky_links": risky_links,
    "double_extension": double_extension,
    "html_smuggling": html_smuggling,
    "bidi_and_archive": bidi_and_archive,
    "type_mismatch": type_mismatch,
    "macro_document": macro_document,
    "mailing_list_forwarded": mailing_list_forwarded,
    "malformed": malformed,
    "date_future": date_future,
    "date_stale": date_stale,
    "spf_softfail": spf_softfail,
    "spf_permerror": spf_permerror,
}


def build_all() -> dict[str, bytes]:
    return {name: build() for name, build in FIXTURES.items()}


def main() -> None:
    for name, raw in build_all().items():
        (HERE / f"{name}.eml").write_bytes(raw)
        print(f"wrote {name}.eml ({len(raw)} bytes)")


if __name__ == "__main__":
    main()
