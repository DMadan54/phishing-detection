"""Shared test setup.

The network guard below enforces the rule that unit tests never touch the
network: every socket connection or DNS lookup to anything other than
loopback raises NetworkBlockedError. Tests marked ``@pytest.mark.live`` are
the only exception, and those are skipped unless selected with ``-m live``.

Loopback must stay allowed because asyncio on Windows talks to itself over a
local socket pair.
"""

import ipaddress
import socket
from typing import Any

import pytest


class NetworkBlockedError(RuntimeError):
    """Raised when a unit test tries to reach the real network."""


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _check_address(address: Any) -> None:
    # AF_UNIX addresses are plain strings or bytes: local, so allowed.
    if isinstance(address, str | bytes):
        return
    host = address[0]
    if not _is_loopback(host):
        raise NetworkBlockedError(f"unit tests must not connect to {host!r}")


@pytest.fixture(autouse=True)
def block_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("live"):
        return

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def guarded_connect(self: socket.socket, address: Any) -> None:
        _check_address(address)
        real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        _check_address(address)
        return real_connect_ex(self, address)

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None and not _is_loopback(host):
            raise NetworkBlockedError(f"unit tests must not resolve {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
