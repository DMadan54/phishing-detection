"""Request body size limits, enforced while the body is being read.

A huge request is the cheapest way to exhaust a server's memory, so the
limit has to bite before the body is held in full. Content-Length can't be
trusted on its own: it can be missing (chunked transfer encoding) or wrong.
So this middleware does two things:

1. If Content-Length is present and already over the limit, it answers 413
   straight away without reading anything.
2. Otherwise it counts the bytes actually received and stops with 413 as
   soon as the count passes the limit.
"""

from collections.abc import Mapping
from http import HTTPStatus

from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

TOO_LARGE = HTTPStatus.REQUEST_ENTITY_TOO_LARGE


def too_large(limit: int) -> HTTPException:
    return HTTPException(TOO_LARGE, f"Request body is larger than the {limit}-byte limit.")


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, limits: Mapping[str, int], default: int) -> None:
        self.app = app
        self.limits = dict(limits)
        self.default = default

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.limits.get(scope["path"], self.default)

        declared = _content_length(scope)
        if declared is not None and declared > limit:
            response = JSONResponse({"detail": too_large(limit).detail}, status_code=TOO_LARGE)
            await response(scope, receive, send)
            return

        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Raised inside the endpoint's body read. Starlette's
                    # exception handling turns it into a 413 response.
                    raise too_large(limit)
            return message

        await self.app(scope, counting_receive, send)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope["headers"]:
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None
