"""The conftest network guard really blocks the network, and only the network."""

import asyncio
import socket

import pytest

from tests.conftest import NetworkBlockedError


def test_dns_lookup_is_blocked() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("example.com", 443)


def test_connect_to_public_address_is_blocked() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(NetworkBlockedError),
    ):
        sock.connect(("93.184.215.14", 443))


def test_loopback_is_allowed() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.socket() as client:
            client.connect(server.getsockname())


async def test_event_loop_still_works() -> None:
    # On Windows the event loop itself uses a loopback socket pair.
    await asyncio.sleep(0)
