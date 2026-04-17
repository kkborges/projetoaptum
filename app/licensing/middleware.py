"""Licensing middleware — enforces license checks on API requests.

Routes are mapped to modules. Unlicensed modules return 403.
Setup mode allows only licensing endpoints and health check.

Uses pure ASGI middleware to avoid BaseHTTPMiddleware issues
(write() before start_response / streaming response bugs).
"""
import json
import logging

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.database import SessionLocal
from app.licensing.manager import license_manager

logger = logging.getLogger(__name__)

# Map URL path prefixes to module names
ROUTE_MODULE_MAP = {
    "/api/scan": "scanner",
    "/api/scans": "scanner",
    "/api/ids": "ids",
    "/api/snmp": "snmp",
    "/api/agent": "agent",
    "/api/pentest": "pentest",
    "/api/logs": "logs",
    "/api/anomalies": "anomaly",
    "/api/topology": "topology",
    "/api/dashboard": "dashboard",
    "/api/hosts": "dashboard",
    "/api/alerts": "dashboard",
}

# Paths that are always allowed (no license required)
ALWAYS_ALLOWED = [
    "/api/licensing",
    "/licensing",
    "/health",
    "/static",
    "/docs",
    "/openapi.json",
    "/redoc",
]


class LicenseMiddleware:
    """Pure ASGI middleware for license enforcement."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Always allow certain paths
        for prefix in ALWAYS_ALLOWED:
            if path.startswith(prefix):
                await self.app(scope, receive, send)
                return

        # Allow root page
        if path == "/":
            await self.app(scope, receive, send)
            return

        # In setup mode, block non-licensing API calls
        if license_manager.is_setup_mode:
            if path.startswith("/api/") and not path.startswith("/api/licensing"):
                await self._send_json(send, 403, {
                    "detail": "Sistema em modo setup. Ative uma licenca em /licensing",
                    "setup_mode": True,
                    "licensing_url": "/licensing",
                })
                return
            await self.app(scope, receive, send)
            return

        # Check module access for API routes
        module_name = None
        for prefix, mod in ROUTE_MODULE_MAP.items():
            if path.startswith(prefix):
                module_name = mod
                break

        if module_name:
            try:
                db = SessionLocal()
                try:
                    result = license_manager.check_module_access(db, module_name)
                    if not result["allowed"]:
                        await self._send_json(send, 403, {
                            "detail": result["reason"],
                            "module": module_name,
                            "licensed": False,
                        })
                        return
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"License check error for {module_name}: {e}")

        await self.app(scope, receive, send)

    async def _send_json(self, send: Send, status: int, body: dict):
        """Send a JSON response directly via ASGI."""
        payload = json.dumps(body).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(payload)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": payload,
        })
