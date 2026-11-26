from phishlens.email.received import ReceivedHop, parse_received, sending_hop


def hops(*values: str) -> list[ReceivedHop]:
    return [parse_received(v, i) for i, v in enumerate(values)]


# Newest first, as in a real message. The bottom hop is forged by the sender.
CHAIN = hops(
    "by 2002:a05:6a10::1 with SMTP id x; Mon, 5 Jan 2026 10:00:07 +0000",
    "from mail.sender.example (mail.sender.example [198.51.100.7]) "
    "by mx.recipient.example with ESMTPS id y; Mon, 5 Jan 2026 10:00:05 +0000",
    "from internal.sender.example ([10.1.2.3]) by mail.sender.example; "
    "Mon, 5 Jan 2026 10:00:01 +0000",
    "from mail.paypal.com (mail.paypal.com [203.0.113.99]) by mx.paypal.com; "
    "Mon, 5 Jan 2026 09:00:00 +0000",
)


def test_parses_the_parts_we_need() -> None:
    hop = CHAIN[1]
    assert hop.from_helo == "mail.sender.example"
    assert hop.from_rdns == "mail.sender.example"
    assert str(hop.from_ip) == "198.51.100.7"
    assert hop.by_host == "mx.recipient.example"


def test_ipv6_literal() -> None:
    hop = parse_received("from x.example (x.example [IPv6:2001:db8::5]) by y.example", 0)
    assert str(hop.from_ip) == "2001:db8::5"


def test_topmost_external_hop_is_chosen() -> None:
    hop = sending_hop(CHAIN, frozenset())
    assert hop is not None and str(hop.from_ip) == "198.51.100.7"


def test_forged_bottom_hops_are_never_chosen() -> None:
    hop = sending_hop(CHAIN, frozenset())
    assert hop is not None and hop.index == 1


def test_trusted_receivers_skip_internal_handoffs() -> None:
    chain = hops(
        "from relay.recipient.example (relay.recipient.example [198.51.100.200]) "
        "by mx2.recipient.example; Mon, 5 Jan 2026 10:00:06 +0000",
        "from mail.sender.example (mail.sender.example [198.51.100.7]) "
        "by relay.recipient.example; Mon, 5 Jan 2026 10:00:05 +0000",
    )
    untrusted = sending_hop(chain, frozenset())
    assert untrusted is not None and untrusted.index == 0
    hop = sending_hop(chain, frozenset({"recipient.example"}))
    assert hop is not None and str(hop.from_ip) == "198.51.100.7"


def test_chain_leaving_trusted_hosts_gives_nothing() -> None:
    chain = hops("from a.example (a.example [198.51.100.1]) by untrusted.example")
    assert sending_hop(chain, frozenset({"recipient.example"})) is None


def test_no_usable_hop() -> None:
    assert sending_hop(hops("by localhost"), frozenset()) is None
    assert sending_hop([], frozenset()) is None


def test_garbage_does_not_raise() -> None:
    for value in ("", ";;;", "from", "from [999.1.1.1] by", "by ; not a date"):
        parse_received(value, 0)
