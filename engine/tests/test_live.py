"""Real-network smoke tests for the outside services. Skipped by default;
run with:  uv run pytest -m live

They check that RDAP and crt.sh still answer in the shape the clients
expect. They never fetch a phishing site.
"""

from datetime import UTC, datetime

import httpx
import pytest

from phishlens.intel.ct import CrtShClient
from phishlens.intel.rdap import HttpRdapClient
from phishlens.services import ServiceUnavailableError, SystemClock

pytestmark = pytest.mark.live


async def test_rdap_knows_an_old_domain() -> None:
    async with httpx.AsyncClient() as http:
        record = await HttpRdapClient(http, SystemClock()).lookup_domain("example.com")
    assert record is not None and record.registered is not None
    assert record.registered < datetime(2000, 1, 1, tzinfo=UTC)


async def test_crtsh_knows_an_old_domain() -> None:
    # crt.sh is a free service and often takes 10+ seconds; when it's too slow
    # the client reports "unavailable" by design, which says nothing about us.
    async with httpx.AsyncClient() as http:
        try:
            first = await CrtShClient(http, SystemClock()).first_certificate("example.org")
        except ServiceUnavailableError as exc:
            pytest.skip(f"crt.sh unavailable right now: {exc}")
    assert first is not None and first < datetime(2020, 1, 1, tzinfo=UTC)
