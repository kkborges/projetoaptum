"""Licensing middleware — enforces license checks on API requests.

Routes are mapped to modules. Unlicensed modules return 403.
Setup mode allows only licensing endpoints and health check.
"""
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

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


class LicenseMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Always allow certain paths
        for prefix in ALWAYS_ALLOWED:
            if path.startswith(prefix):
                return await call_next(request)

        # Allow root page
        if path == "/":
            return await call_next(request)

        # In setup mode, redirect non-API to licensing page
        if license_manager.is_setup_mode:
            if path.startswith("/api/") and not path.startswith("/api/licensing"):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Sistema em modo setup. Ative uma licenca em /licensing",
                        "setup_mode": True,
                        "licensing_url": "/licensing",
                    },
                )
            return await call_next(request)

        # Check module access for API routes
        module_name = None
        for prefix, mod in ROUTE_MODULE_MAP.items():
            if path.startswith(prefix):
                module_name = mod
                break

        if module_name:
            db = SessionLocal()
            try:
                result = license_manager.check_module_access(db, module_name)
                if not result["allowed"]:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": result["reason"],
                            "module": module_name,
                            "licensed": False,
                        },
                    )
            finally:
                db.close()

        return await call_next(request)
