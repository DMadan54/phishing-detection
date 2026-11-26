"""Optional reputation lookups: Google Safe Browsing, urlscan.io, VirusTotal.

Each runs only when its API key is set, and each finding names its source,
because "Google Safe Browsing lists this URL as phishing" means something
quite different from "two of seventy VirusTotal engines are suspicious".

Privacy: these services receive the URL (or its domain), so using them sends
user data to a third party. That's why they're off unless configured. They
are only ever asked about existing knowledge: nothing is submitted for a new
scan, because urlscan scans can be public and VirusTotal submissions are
shared with its partners.
"""

import base64
import os
from dataclasses import dataclass
from datetime import timedelta
from typing import ClassVar, Protocol

import httpx

from phishlens.findings import Severity
from phishlens.intel.cache import TtlCache
from phishlens.services import Clock, ServiceUnavailableError
from phishlens.url.parse import ParsedUrl

TIMEOUT = 8.0


@dataclass(frozen=True, slots=True)
class Verdict:
    source: str  # "Google Safe Browsing"
    finding: str  # last part of the finding id: "safe_browsing"
    severity: Severity
    summary: str  # completes "<source> ...": "lists this URL as social engineering"


class ReputationSource(Protocol):
    name: str

    async def lookup(self, url: ParsedUrl) -> Verdict | None:
        """A verdict if the source considers the URL harmful, None if it doesn't.
        Raises ServiceUnavailableError when it can't say."""
        ...


class _Cached:
    def __init__(self, clock: Clock) -> None:
        self._cache: TtlCache[str, tuple[Verdict | None]] = TtlCache(clock, timedelta(hours=1))

    async def _cached(self, key: str, fetch: "_Fetch") -> Verdict | None:
        hit = self._cache.get(key)
        if hit is not None:
            return hit[0]
        verdict = await fetch()
        self._cache.put(key, (verdict,))
        return verdict


class _Fetch(Protocol):
    async def __call__(self) -> Verdict | None: ...


async def _send(http: httpx.AsyncClient, request: httpx.Request, source: str) -> httpx.Response:
    try:
        return await http.send(request, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise ServiceUnavailableError(f"{source} request failed ({type(exc).__name__})") from None


class SafeBrowsing(_Cached):
    """Google Safe Browsing Lookup API (v4): is this exact URL on Google's lists?"""

    name = "Google Safe Browsing"
    THREATS = (
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    )
    WORDS: ClassVar[dict[str, str]] = {
        "SOCIAL_ENGINEERING": "phishing or social engineering",
        "MALWARE": "malware",
        "UNWANTED_SOFTWARE": "unwanted software",
        "POTENTIALLY_HARMFUL_APPLICATION": "a potentially harmful app",
    }

    def __init__(self, http: httpx.AsyncClient, clock: Clock, key: str) -> None:
        super().__init__(clock)
        self._http, self._key = http, key

    async def lookup(self, url: ParsedUrl) -> Verdict | None:
        async def fetch() -> Verdict | None:
            body = {
                "client": {"clientId": "phishlens", "clientVersion": "0.1"},
                "threatInfo": {
                    "threatTypes": list(self.THREATS),
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url.href}],
                },
            }
            request = self._http.build_request(
                "POST",
                "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                params={"key": self._key},
                json=body,
                timeout=TIMEOUT,
            )
            response = await _send(self._http, request, self.name)
            if response.status_code != 200:
                raise ServiceUnavailableError(f"{self.name} answered {response.status_code}")
            matches = response.json().get("matches") or []
            if not matches:
                return None
            kinds = sorted({self.WORDS.get(m.get("threatType"), "a threat") for m in matches})
            return Verdict(
                self.name,
                "safe_browsing",
                Severity.HIGH,
                f"lists this URL as {' and '.join(kinds)}",
            )

        return await self._cached(url.href, fetch)


class UrlScan(_Cached):
    """urlscan.io search: have earlier scans of this domain been judged malicious?
    Searches only; never submits a scan."""

    name = "urlscan.io"

    def __init__(self, http: httpx.AsyncClient, clock: Clock, key: str) -> None:
        super().__init__(clock)
        self._http, self._key = http, key

    async def lookup(self, url: ParsedUrl) -> Verdict | None:
        domain = url.host
        if not domain:
            return None

        async def fetch() -> Verdict | None:
            request = self._http.build_request(
                "GET",
                "https://urlscan.io/api/v1/search/",
                params={"q": f'page.domain:"{domain}" AND verdicts.malicious:true', "size": "1"},
                headers={"API-Key": self._key},
                timeout=TIMEOUT,
            )
            response = await _send(self._http, request, self.name)
            if response.status_code != 200:
                raise ServiceUnavailableError(f"{self.name} answered {response.status_code}")
            total = int(response.json().get("total") or 0)
            if total == 0:
                return None
            return Verdict(
                self.name,
                "urlscan",
                Severity.HIGH,
                f"has {total} earlier scan(s) of {domain} judged malicious",
            )

        return await self._cached(domain, fetch)


class VirusTotal(_Cached):
    """VirusTotal URL report: what did its scanning engines say last time?
    Looks up the existing report only; never submits the URL."""

    name = "VirusTotal"

    def __init__(self, http: httpx.AsyncClient, clock: Clock, key: str) -> None:
        super().__init__(clock)
        self._http, self._key = http, key

    async def lookup(self, url: ParsedUrl) -> Verdict | None:
        async def fetch() -> Verdict | None:
            # VirusTotal identifies a URL by its unpadded URL-safe base64.
            ident = base64.urlsafe_b64encode(url.href.encode()).decode().rstrip("=")
            request = self._http.build_request(
                "GET",
                f"https://www.virustotal.com/api/v3/urls/{ident}",
                headers={"x-apikey": self._key},
                timeout=TIMEOUT,
            )
            response = await _send(self._http, request, self.name)
            if response.status_code == 404:
                return None  # never analysed: unknown to VirusTotal, not clean
            if response.status_code != 200:
                raise ServiceUnavailableError(f"{self.name} answered {response.status_code}")
            stats = (
                response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            if malicious == 0 and suspicious == 0:
                return None
            total = sum(int(v or 0) for v in stats.values())
            return Verdict(
                self.name,
                "virustotal",
                Severity.HIGH if malicious >= 2 else Severity.MEDIUM,
                f"reports {malicious} of {total} engines calling this URL malicious"
                + (f" and {suspicious} suspicious" if suspicious else ""),
            )

        return await self._cached(url.href, fetch)


def configured_sources(http: httpx.AsyncClient, clock: Clock) -> list[ReputationSource]:
    """The sources whose API keys are set in the environment."""
    sources: list[ReputationSource] = []
    if key := os.environ.get("PHISHLENS_SAFE_BROWSING_API_KEY"):
        sources.append(SafeBrowsing(http, clock, key))
    if key := os.environ.get("PHISHLENS_URLSCAN_API_KEY"):
        sources.append(UrlScan(http, clock, key))
    if key := os.environ.get("PHISHLENS_VIRUSTOTAL_API_KEY"):
        sources.append(VirusTotal(http, clock, key))
    return sources
