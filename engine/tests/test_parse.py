"""The parser on small inline messages. Whole fixtures are tested later."""

from datetime import UTC, datetime

from phishlens.email.parse import parse_email

SIMPLE = (
    b"Return-Path: <bounce@mail.shop.example>\r\n"
    b"Received: from mx.shop.example (mx.shop.example [192.0.2.10])\r\n"
    b"\tby mx.recipient.example with ESMTPS; Mon, 5 Jan 2026 10:00:05 +0000\r\n"
    b"From: =?utf-8?q?Shop_=C3=9Cber?= <news@shop.example>\r\n"
    b"Reply-To: help@shop.example\r\n"
    b"To: you@recipient.example\r\n"
    b"Subject: Hello\r\n"
    b"Message-ID: <abc123@shop.example>\r\n"
    b"Date: Mon, 5 Jan 2026 10:00:00 +0000\r\n"
    b"List-Id: <news.shop.example>\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="b1"\r\n'
    b"\r\n"
    b"--b1\r\n"
    b'Content-Type: multipart/alternative; boundary="b2"\r\n'
    b"\r\n"
    b"--b2\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Visit https://shop.example/offers. Thanks!\r\n"
    b"--b2\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><head><style>p{}</style></head><body><p>Hi</p>"
    b'<a href=" https://evil.test/x ">www.shop.example</a>'
    b'<a href="https://shop.example/"><img alt="Shop logo"></a>'
    b"<script>var hidden = 1;</script></body></html>\r\n"
    b"--b2--\r\n"
    b"--b1\r\n"
    b"Content-Type: application/pdf\r\n"
    b'Content-Disposition: attachment; filename="invoice.pdf"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"JVBERi0xLjcK\r\n"
    b"--b1--\r\n"
)


def test_headers_and_addresses() -> None:
    parsed = parse_email(SIMPLE)
    sender = parsed.from_address
    assert sender is not None
    assert (sender.display_name, sender.addr_spec, sender.domain) == (
        "Shop Über",
        "news@shop.example",
        "shop.example",
    )
    assert [a.addr_spec for a in parsed.reply_to] == ["help@shop.example"]
    assert parsed.return_path == "bounce@mail.shop.example"
    assert parsed.message_id == "abc123@shop.example"
    assert parsed.list_id == "<news.shop.example>"
    assert parsed.subject == "Hello"
    assert parsed.date == datetime(2026, 1, 5, 10, 0, tzinfo=UTC)


def test_header_spans_point_into_the_raw_bytes() -> None:
    parsed = parse_email(SIMPLE)
    for name in ("From", "Received", "Subject"):
        field = parsed.header(name)
        assert field is not None and field.span is not None
        assert SIMPLE[field.span.start : field.span.end].startswith(name.encode() + b":")
    received = parsed.header("Received")
    assert received is not None and received.span is not None
    # A folded header's span covers its continuation line too.
    assert SIMPLE[received.span.start : received.span.end].endswith(b"+0000")


def test_received_chain() -> None:
    (hop,) = parse_email(SIMPLE).received
    assert str(hop.from_ip) == "192.0.2.10"
    assert hop.from_helo == "mx.shop.example"
    assert hop.by_host == "mx.recipient.example"
    assert hop.timestamp == datetime(2026, 1, 5, 10, 0, 5, tzinfo=UTC)


def test_bodies_and_links() -> None:
    parsed = parse_email(SIMPLE)
    # The CRLF before a MIME boundary belongs to the boundary (RFC 2046).
    assert parsed.text_bodies == ("Visit https://shop.example/offers. Thanks!",)
    assert "hidden" not in parsed.html_text[0]
    assert "p{}" not in parsed.html_text[0]
    links = [(link.href, link.text, link.source) for link in parsed.links]
    assert links == [
        ("https://shop.example/offers", "https://shop.example/offers", "text"),
        ("https://evil.test/x", "www.shop.example", "html"),
        ("https://shop.example/", "Shop logo", "html"),
    ]


def test_attachments() -> None:
    (attachment,) = parse_email(SIMPLE).attachments
    assert attachment.filename == "invoice.pdf"
    assert attachment.declared_type == "application/pdf"
    assert attachment.sniffed_type == "application/pdf"
    assert attachment.content == b"%PDF-1.7\n"
    assert attachment.size == 9


def test_multiple_from_headers_mean_no_single_sender() -> None:
    parsed = parse_email(b"From: a@one.example\r\nFrom: b@two.example\r\n\r\nhi")
    assert parsed.from_header_count == 2
    assert parsed.from_address is None


def test_null_return_path() -> None:
    assert parse_email(b"Return-Path: <>\r\nFrom: a@b.example\r\n\r\nx").return_path == ""


def test_garbage_never_raises() -> None:
    for raw in (b"", b"\x00\xff\xfe", b"no headers at all", b":\r\n:\r\n\r\n", b"From: <<<@@>\r\n"):
        parsed = parse_email(raw)
        assert parsed.raw == raw


def test_missing_headers_are_recorded() -> None:
    assert "NoHeaders" in parse_email(b"").defects


def test_part_count_is_capped() -> None:
    parts = b"".join(b"--b\r\nContent-Type: text/plain\r\n\r\nx\r\n" for _ in range(600))
    raw = b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n' + parts + b"--b--\r\n"
    parsed = parse_email(raw)
    assert "TooManyParts" in parsed.defects
    assert len(parsed.text_bodies) < 600
