"""Domain registration dates from RDAP.

RDAP (RFC 9082/9083) is the structured, JSON replacement for WHOIS: one
HTTPS request returns the domain's record, including an "events" list where
"registration" says when it was first registered. A domain registered a few
days ago and already used in a link is one of the strongest phishing signals
there is, because phishing sites are short-lived and set up just in time.

Which server to ask comes from IANA's bootstrap file (RFC 9224), shipped as
a snapshot in phishlens/data/ (refresh with scripts/fetch_rdap_bootstrap.py).
Since ICANN retired WHOIS for generic TLDs in January 2025, RDAP is the
authoritative source for them. Some country TLDs (for example .de, .io, .co)
publish no RDAP server; their age is reported as unknown. A WHOIS fallback
could fill that gap later.
"""

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources
from urllib.parse import quote

import httpx

from phishlens.domains import split_domain
from phishlens.intel.cache import TtlCache
from phishlens.services import Clock, RdapRecord, ServiceUnavailableError

TIMEOUT = 5.0
MAX_BYTES = 512 * 1024
# Cached for "this domain has no registration record", so a repeat lookup
# gives the same answer without asking again.
_NOT_FOUND = RdapRecord("", None)


@cache
def bootstrap() -> dict[str, str]:
    """TLD -> RDAP base URL, from the shipped IANA snapshot."""
    data = json.loads(
        (resources.files("phishlens") / "data" / "iana-rdap-dns.json").read_text(encoding="utf-8")
    )
    servers: dict[str, str] = {}
    for tlds, urls in data["services"]:
        https = [u for u in urls if u.startswith("https://")]
        if https:
            for tld in tlds:
                servers[tld.lower()] = https[0] if https[0].endswith("/") else https[0] + "/"
    return servers


def registration_date(record: Mapping[str, object]) -> datetime | None:
    events = record.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                when = datetime.fromisoformat(str(event.get("eventDate")).replace("Z", "+00:00"))
            except ValueError:
                return None
            return when if when.tzinfo else when.replace(tzinfo=UTC)
    return None


class HttpRdapClient:
    def __init__(
        self, http: httpx.AsyncClient, clock: Clock, servers: dict[str, str] | None = None
    ):
        self._http = http
        self._servers = servers if servers is not None else bootstrap()
        self._cache: TtlCache[str, RdapRecord] = TtlCache(clock, timedelta(hours=24))

    async def lookup_domain(self, domain: str) -> RdapRecord | None:
        registrable = split_domain(domain).registrable
        cached = self._cache.get(registrable)
        if cached is not None:
            return None if cached is _NOT_FOUND else cached
        tld = registrable.rpartition(".")[2]
        base = self._servers.get(tld)
        if base is None:
            raise ServiceUnavailableError(f"no RDAP server for .{tld}")
        try:
            response = await self._http.get(
                f"{base}domain/{quote(registrable, safe='')}",
                headers={"Accept": "application/rdap+json"},
                timeout=TIMEOUT,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise ServiceUnavailableError(f"RDAP request failed ({type(exc).__name__})") from None
        if response.status_code == 404:
            self._cache.put(registrable, _NOT_FOUND)
            return None
        if response.status_code != 200 or len(response.content) > MAX_BYTES:
            raise ServiceUnavailableError(f"RDAP answered {response.status_code}")
        try:
            data = response.json()
        except ValueError:
            raise ServiceUnavailableError("RDAP answer wasn't JSON") from None
        record = RdapRecord(
            registrable, registration_date(data) if isinstance(data, dict) else None
        )
        self._cache.put(registrable, record)
        return record
