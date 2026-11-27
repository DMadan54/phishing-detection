"""The HTTP API.

Run it with:  uv run uvicorn --factory phishlens.api:create_app --reload

Nothing here stores what it receives: the email or URL lives in memory for
the length of one request. Emails are sent as the raw body (not multipart),
because multipart uploads over 1 MB are spooled to a temporary file on disk.

/analyse/url follows the URL's redirects (through the SSRF-guarded fetcher)
unless the request says "follow_redirects": false. Links inside emails are
never fetched.
"""

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from http import HTTPStatus
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from phishlens import __version__
from phishlens.dnsbridge import CachingDns
from phishlens.email.parse import parse_email
from phishlens.findings import CheckContext, Finding
from phishlens.intel.ct import CrtShClient
from phishlens.intel.rdap import HttpRdapClient
from phishlens.intel.reputation import configured_sources
from phishlens.limits import BodySizeLimitMiddleware
from phishlens.net.safe_fetch import SafeFetcher
from phishlens.registry import Registry, default_registry, parse_disabled
from phishlens.runner import run_checks
from phishlens.services import DnspythonResolver, SystemClock
from phishlens.url.parse import parse_url

MAX_EMAIL_BYTES = 10 * 1024 * 1024
MAX_URL_CHARS = 2048
# The URL arrives wrapped in JSON, so its route allows a little more than the
# URL itself. The 2048-character URL limit is checked separately.
MAX_URL_BODY_BYTES = 16 * 1024
MAX_OTHER_BODY_BYTES = 16 * 1024

EMAIL_CONTENT_TYPES = frozenset({"message/rfc822", "text/plain"})

# Tells the generated /docs page that the email route takes a raw body.
_EMAIL_BODY_DOCS: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "description": "The raw RFC 5322 message, for example the contents of a .eml file.",
        "content": {
            "message/rfc822": {"schema": {"type": "string", "format": "binary"}},
            "text/plain": {"schema": {"type": "string"}},
        },
    }
}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class UrlRequest(_Frozen):
    url: str = Field(min_length=1)
    # Following redirects fetches the URL (safely, but it does contact the
    # site, which an attacker can notice). Turn it off to only read the URL.
    follow_redirects: bool = True


class Report(_Frozen):
    """The analysis of one email or URL.

    The verdict and score are added with the scoring step; until then a
    report is the list of findings and which checks produced them.
    """

    kind: Literal["email", "url"]
    findings: list[Finding]
    checks_run: list[str]


class Health(_Frozen):
    status: Literal["ok"] = "ok"
    version: str = __version__


@dataclass
class _State:
    context: CheckContext


def real_context(http: httpx.AsyncClient) -> CheckContext:
    """The production services. http is only for fixed API hosts (RDAP,
    crt.sh, reputation); user-supplied URLs go through SafeFetcher."""
    clock = SystemClock()
    resolver = DnspythonResolver()
    return CheckContext(
        dns=resolver,
        rdap=HttpRdapClient(http, clock),
        http=http,
        clock=clock,
        fetcher=SafeFetcher(dns=resolver),
        ct=CrtShClient(http, clock),
    )


def create_app(registry: Registry | None = None, context: CheckContext | None = None) -> FastAPI:
    """Build the app. Tests pass their own registry and a context of fakes."""
    owned_http: httpx.AsyncClient | None = None
    if context is None:
        owned_http = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
        context = real_context(owned_http)
    if registry is None:
        disabled = parse_disabled(os.environ.get("PHISHLENS_DISABLED_CHECKS"))
        sources = configured_sources(context.http, context.clock)
        registry = default_registry(reputation=sources).without(disabled)
    checks = registry
    state = _State(context=context)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owned_http is not None:
                await owned_http.aclose()

    app = FastAPI(title="PhishLens", version=__version__, lifespan=lifespan)
    app.add_middleware(
        BodySizeLimitMiddleware,
        limits={"/analyse/email": MAX_EMAIL_BYTES, "/analyse/url": MAX_URL_BODY_BYTES},
        default=MAX_OTHER_BODY_BYTES,
    )

    def current_context() -> CheckContext:
        """The context for one request: shared services plus a fresh DNS cache."""
        return replace(state.context, dns=CachingDns(state.context.dns))

    @app.get("/health")
    async def health() -> Health:
        return Health()

    @app.post("/analyse/email", openapi_extra=_EMAIL_BODY_DOCS)
    async def analyse_email(request: Request) -> Report:
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type not in EMAIL_CONTENT_TYPES:
            raise HTTPException(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "Send the raw email as the request body with Content-Type message/rfc822.",
            )
        raw = await request.body()
        if not raw.strip():
            raise HTTPException(HTTPStatus.UNPROCESSABLE_ENTITY, "The request body is empty.")

        # Parsing a large message is CPU work, so keep it off the event loop.
        parsed = await asyncio.to_thread(parse_email, raw)
        findings = await run_checks(checks.email_checks, parsed, current_context())
        return Report(
            kind="email", findings=findings, checks_run=[c.name for c in checks.email_checks]
        )

    @app.post("/analyse/url")
    async def analyse_url(body: UrlRequest) -> Report:
        if len(body.url) > MAX_URL_CHARS:
            raise HTTPException(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                f"The URL is longer than {MAX_URL_CHARS} characters.",
            )
        url_checks = [
            c for c in checks.url_checks if body.follow_redirects or c.name != "url.redirect"
        ]
        findings = await run_checks(url_checks, parse_url(body.url), current_context())
        return Report(kind="url", findings=findings, checks_run=[c.name for c in url_checks])

    return app
