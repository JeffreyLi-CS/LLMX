"""
HTTP middleware for the LLMX backend.

RequestIDMiddleware
    - Accepts an incoming X-Request-ID header (for trace correlation from the
      extension or a gateway) or generates a new UUID4.
    - Stores the ID on request.state and in structlog's context-local store so
      every log line emitted during the request carries it automatically.
    - Echoes the ID back on the response as X-Request-ID.
    - Logs request start and completion with method, path, and status code.
"""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from structlog.contextvars import bind_contextvars, clear_contextvars

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Reset any context left over from a previous request on this worker.
        clear_contextvars()

        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        bind_contextvars(request_id=request_id)
        request.state.request_id = request_id

        start = time.perf_counter()
        logger.info(
            "http.request.started",
            method=request.method,
            path=request.url.path,
        )

        response = await call_next(request)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "http.request.completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
        )

        return response
