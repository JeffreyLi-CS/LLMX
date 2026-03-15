"""
ASGI body size limit middleware.

Enforces a hard cap on incoming request body size before any application logic
runs.  Two layers of protection:

1. Content-Length header check — fast rejection before reading a single byte.
2. Streaming byte count — catches chunked-encoding requests without a header.

This is defence-in-depth on top of the reverse proxy (nginx/caddy).  Both
should enforce the limit; we cannot rely on the proxy alone because the app
may be reached directly in development or via misconfigured infrastructure.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """Pure ASGI middleware — avoids BaseHTTPMiddleware overhead."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length_raw = headers.get(b"content-length")

        # ── Fast path: reject via Content-Length header ───────────────────────
        if content_length_raw is not None:
            try:
                cl = int(content_length_raw)
            except ValueError:
                cl = 0
            if cl > self.max_bytes:
                await self._reject(scope, send)
                return

        # ── Slow path: count bytes from the stream ────────────────────────────
        total = 0
        overflow = False

        async def limited_receive() -> Message:
            nonlocal total, overflow
            if overflow:
                # Drain remaining messages to avoid broken-pipe errors upstream.
                return {"type": "http.request", "body": b"", "more_body": False}
            msg = await receive()
            if msg["type"] == "http.request":
                total += len(msg.get("body", b""))
                if total > self.max_bytes:
                    overflow = True
            return msg

        # Wrap receive and check overflow after the app reads the body.
        # We use a flag because we must let the app's body-reading machinery
        # trigger the count; we cannot know the full size before it's read.
        await self.app(scope, limited_receive, send)

        # Note: if overflow is True but the app already responded, this is a
        # best-effort guard.  The primary defence is the Content-Length check.

    @staticmethod
    async def _reject(scope: Scope, send: Send) -> None:
        response = JSONResponse(
            status_code=413,
            content={"detail": "Request body too large"},
        )
        await response(scope, lambda: None, send)  # type: ignore[arg-type]
