"""HTTP access logging.

Pure ASGI middleware (not BaseHTTPMiddleware) so MCP's SSE streaming
responses pass through unbuffered. Every request gets a short id, echoed in
the X-Request-ID response header and included in the access log line.
"""

from __future__ import annotations

import logging
import time
import uuid

logger = logging.getLogger("fes_mcp.access")

QUIET_PATHS = {"/healthz"}


class AccessLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex[:8]
        start = time.perf_counter()
        status_holder = {"status": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = message.setdefault("headers", [])
                headers.append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope.get("path", "")
            if path not in QUIET_PATHS:
                client = scope.get("client") or ("-", 0)
                duration_ms = (time.perf_counter() - start) * 1000
                logger.info(
                    "%s %s -> %d %.0fms ip=%s rid=%s",
                    scope.get("method", "-"),
                    path,
                    status_holder["status"],
                    duration_ms,
                    client[0],
                    request_id,
                )
