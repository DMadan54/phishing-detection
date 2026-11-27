from collections.abc import AsyncIterator

import httpx
import pytest

from phishlens.api import MAX_EMAIL_BYTES, MAX_URL_CHARS, create_app
from phishlens.email.config import EmailConfig
from phishlens.registry import Registry, default_registry
from phishlens.services import Fetcher
from tests.checks import StaticCheck
from tests.fakes import make_context

EMAIL = b"From: Sender <sender@example.com>\r\nTo: you@example.com\r\nSubject: Hi\r\n\r\nHello\r\n"
RFC822 = {"Content-Type": "message/rfc822"}


def make_client(registry: Registry | None = None) -> httpx.AsyncClient:
    app = create_app(registry=registry or Registry(), context=make_context())
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with make_client() as c:
        yield c


# --- health ------------------------------------------------------------------


async def test_health(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


# --- email -------------------------------------------------------------------


async def test_email_returns_empty_report(client: httpx.AsyncClient) -> None:
    response = await client.post("/analyse/email", content=EMAIL, headers=RFC822)
    assert response.status_code == 200
    assert response.json() == {"kind": "email", "findings": [], "checks_run": []}


async def test_email_accepts_text_plain_with_charset(client: httpx.AsyncClient) -> None:
    headers = {"Content-Type": "text/plain; charset=utf-8"}
    response = await client.post("/analyse/email", content=EMAIL, headers=headers)
    assert response.status_code == 200


async def test_malformed_email_is_analysed_not_rejected(client: httpx.AsyncClient) -> None:
    # A message that isn't valid RFC 5322 is evidence for the checks.
    response = await client.post("/analyse/email", content=b"not an email at all", headers=RFC822)
    assert response.status_code == 200


async def test_email_runs_registered_checks() -> None:
    registry = Registry(email_checks=(StaticCheck("email.static"),))
    async with make_client(registry) as client:
        response = await client.post("/analyse/email", content=EMAIL, headers=RFC822)
    report = response.json()
    assert report["checks_run"] == ["email.static"]
    assert [f["id"] for f in report["findings"]] == ["email.static.seen"]


async def test_email_at_the_limit_is_accepted(client: httpx.AsyncClient) -> None:
    body = EMAIL + b"x" * (MAX_EMAIL_BYTES - len(EMAIL))
    response = await client.post("/analyse/email", content=body, headers=RFC822)
    assert response.status_code == 200


async def test_oversized_email_with_content_length_is_413(client: httpx.AsyncClient) -> None:
    body = b"x" * (MAX_EMAIL_BYTES + 1)
    response = await client.post("/analyse/email", content=body, headers=RFC822)
    assert response.status_code == 413


async def test_oversized_chunked_email_is_413(client: httpx.AsyncClient) -> None:
    # No Content-Length: the limit must be enforced by counting bytes.
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(11):
            yield b"x" * (1024 * 1024)

    response = await client.post("/analyse/email", content=chunks(), headers=RFC822)
    assert "content-length" not in response.request.headers
    assert response.status_code == 413


async def test_empty_email_is_422(client: httpx.AsyncClient) -> None:
    response = await client.post("/analyse/email", content=b"  \r\n", headers=RFC822)
    assert response.status_code == 422


async def test_wrong_email_content_type_is_415(client: httpx.AsyncClient) -> None:
    response = await client.post("/analyse/email", json={"email": "hi"})
    assert response.status_code == 415


# --- url ---------------------------------------------------------------------


async def test_url_returns_empty_report(client: httpx.AsyncClient) -> None:
    response = await client.post("/analyse/url", json={"url": "https://example.com/login"})
    assert response.status_code == 200
    assert response.json() == {"kind": "url", "findings": [], "checks_run": []}


async def test_malformed_url_is_analysed_not_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post("/analyse/url", json={"url": "htps//not a url"})
    assert response.status_code == 200


async def test_url_at_the_limit_is_accepted(client: httpx.AsyncClient) -> None:
    url = "https://example.com/" + "a" * (MAX_URL_CHARS - len("https://example.com/"))
    assert len(url) == MAX_URL_CHARS
    response = await client.post("/analyse/url", json={"url": url})
    assert response.status_code == 200


async def test_overlong_url_is_413(client: httpx.AsyncClient) -> None:
    url = "https://example.com/" + "a" * MAX_URL_CHARS
    response = await client.post("/analyse/url", json={"url": url})
    assert response.status_code == 413


async def test_oversized_url_body_is_413(client: httpx.AsyncClient) -> None:
    response = await client.post("/analyse/url", json={"url": "x", "padding": "p" * 20_000})
    assert response.status_code == 413


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        b"{}",
        b'{"url": 42}',
        b'{"url": ""}',
        b'{"url": "https://example.com", "extra": 1}',
        b'["https://example.com"]',
    ],
    ids=["invalid-json", "missing-url", "not-a-string", "empty", "unknown-field", "not-an-object"],
)
async def test_malformed_url_request_is_422(client: httpx.AsyncClient, body: bytes) -> None:
    headers = {"Content-Type": "application/json"}
    response = await client.post("/analyse/url", content=body, headers=headers)
    assert response.status_code == 422


# --- url, with the real URL checks -------------------------------------------


def url_client(fetcher: Fetcher | None = None) -> httpx.AsyncClient:
    context = make_context(fetcher=fetcher)
    app = create_app(registry=default_registry(EmailConfig()), context=context)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def test_url_route_runs_the_url_checks() -> None:
    async with url_client() as client:
        response = await client.post(
            "/analyse/url",
            json={"url": "https://paypal.com@login.paypa1.com/signin", "follow_redirects": False},
        )
    report = response.json()
    ids = {f["id"] for f in report["findings"]}
    assert {"url.userinfo.present", "url.lookalike.character_swap"} <= ids
    assert "url.redirect" not in report["checks_run"]
    assert "url.lexical" not in report["checks_run"]  # checks are named by part
    assert "url.host" in report["checks_run"]


async def test_url_route_follows_redirects_by_default() -> None:
    from phishlens.net.safe_fetch import SafeFetcher
    from tests.fakes import FakeConnector, FakeDns, redirect

    dns = FakeDns().add("bit.ly", "A", "93.184.215.14").add("paypa1.com", "A", "93.184.215.14")
    connector = FakeConnector({"https://bit.ly/x": redirect("https://paypa1.com/login")})
    async with url_client(SafeFetcher(dns=dns, connector=connector)) as client:
        response = await client.post("/analyse/url", json={"url": "https://bit.ly/x"})
    report = response.json()
    assert "url.redirect" in report["checks_run"]
    assert "url.redirect.to_lookalike" in {f["id"] for f in report["findings"]}


async def test_bad_follow_redirects_value_is_422(client: httpx.AsyncClient) -> None:
    body = {"url": "https://example.com", "follow_redirects": "maybe"}
    response = await client.post("/analyse/url", json=body)
    assert response.status_code == 422
