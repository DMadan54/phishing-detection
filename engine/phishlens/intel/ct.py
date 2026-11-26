"""When did a domain get its first TLS certificate?

Certificate Transparency (RFC 9162) requires every publicly trusted TLS
certificate to be published in public, append-only logs before browsers
accept it. So the logs show when a domain first got a certificate, which is
usually when its HTTPS site went live. A sign-in page on a domain whose
first certificate is two days old is a strong signal.

crt.sh is a free search over those logs. It is slow and asks for gentle use,
so requests are limited to one every 5 seconds, answers are cached for a
day, the response size is capped, and any failure means "unknown".
"""

import json
import time
from datetime import UTC, datetime, timedelta

import httpx

from phishlens.domains import split_domain
from phishlens.intel.cache import RateLimiter, TtlCache
from phishlens.services import Clock, ServiceUnavailableError

URL = "https://crt.sh/"
TIMEOUT = 10.0
MAX_BYTES = 4 * 1024 * 1024  # a domain with more history than this is long established
# Cached for "no certificate is logged", so it expires like any other answer.
_NO_CERTIFICATE = datetime.min.replace(tzinfo=UTC)


class CrtShClient:
    def __init__(self, http: httpx.AsyncClient, clock: Clock, limiter: RateLimiter | None = None):
        self._http = http
        self._cache: TtlCache[str, datetime] = TtlCache(clock, timedelta(hours=24))
        self._limiter = limiter or RateLimiter(interval=5.0, max_wait=5.0, now=time.monotonic)

    async def first_certificate(self, domain: str) -> datetime | None:
        registrable = split_domain(domain).registrable
        cached = self._cache.get(registrable)
        if cached is not None:
            return None if cached == _NO_CERTIFICATE else cached
        if not await self._limiter.acquire():
            raise ServiceUnavailableError("crt.sh rate limit reached")
        try:
            async with self._http.stream(
                "GET",
                URL,
                params={"q": registrable, "output": "json"},
                timeout=TIMEOUT,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raise ServiceUnavailableError(f"crt.sh answered {response.status_code}")
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_BYTES:
                        raise ServiceUnavailableError("crt.sh history too large to read")
        except httpx.HTTPError as exc:
            raise ServiceUnavailableError(f"crt.sh request failed ({type(exc).__name__})") from None

        try:
            entries = json.loads(body or b"[]")
        except ValueError:
            raise ServiceUnavailableError("crt.sh answer wasn't JSON") from None
        dates = []
        for entry in entries if isinstance(entries, list) else []:
            try:
                issued = datetime.fromisoformat(str(entry["not_before"]))
            except (KeyError, TypeError, ValueError):
                continue
            dates.append(issued if issued.tzinfo else issued.replace(tzinfo=UTC))
        first = min(dates) if dates else None
        self._cache.put(registrable, first or _NO_CERTIFICATE)
        return first
