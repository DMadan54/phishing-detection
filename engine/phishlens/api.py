"""The HTTP API.

Run it with:  uv run uvicorn --factory phishlens.api:create_app --reload

Nothing here stores what it receives: the email or URL lives in memory for
the length of one request. Emails are sent as the raw body (not multipart),
because multipart uploads over 1 MB are spooled to a temporary file on disk.
"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from phishlens import __version__
from phishlens.findings import CheckContext, Finding
from phishlens.limits import BodySizeLimitMiddleware
from phishlens.registry import Registry, default_registry, parse_disabled
from phishlens.runner import run_checks
from phishlens.services import SystemClock, UnconfiguredDns, UnconfiguredRdap
from phishlens.subjects import RawEmail, RawUrl

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
    context: CheckContext | None


def create_app(registry: Registry | None = None, context: CheckContext | None = None) -> FastAPI:
    """Build the app. Tests pass their own registry and a context of fakes."""
    if registry is None:
        disabled = parse_disabled(os.environ.get("PHISHLENS_DISABLED_CHECKS"))
        registry = default_registry().without(disabled)
    checks = registry
    state = _State(context=context)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if state.context is not None:
            yield
            return
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as http:
            state.context = CheckContext(
                dns=UnconfiguredDns(), rdap=UnconfiguredRdap(), http=http, clock=SystemClock()
            )
            yield
            state.context = None

    app = FastAPI(title="PhishLens", version=__version__, lifespan=lifespan)
    app.add_middleware(
        BodySizeLimitMiddleware,
        limits={"/analyse/email": MAX_EMAIL_BYTES, "/analyse/url": MAX_URL_BODY_BYTES},
        default=MAX_OTHER_BODY_BYTES,
    )

    def current_context() -> CheckContext:
        if state.context is None:
            raise RuntimeError("the app was started without a check context")
        return state.context

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

        findings = await run_checks(checks.email_checks, RawEmail(raw), current_context())
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
        findings = await run_checks(checks.url_checks, RawUrl(body.url), current_context())
        return Report(kind="url", findings=findings, checks_run=[c.name for c in checks.url_checks])

    return app
