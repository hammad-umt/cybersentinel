"""OpenAPI / Swagger configuration — single Bearer Authorize button at the top."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

# Routes that stay public in Swagger (no lock icon, no Bearer required).
_AUTH_PUBLIC_PATHS = {
    "/api/v1/auth/token",
    "/api/v1/auth/register",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
    "/api/v1/auth/reset-password/validate",
}


def configure_openapi(app: FastAPI) -> None:
    """Expose one HTTP Bearer scheme so Swagger shows a single top Authorize button."""

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=(
                "CyberSentinel SOC API.\n\n"
                "**How to authenticate in Swagger:**\n"
                "1. Call `POST /api/v1/auth/token` (email as `username`, plus password) to get an `access_token`.\n"
                "2. Click **Authorize** at the top of this page and paste the token.\n"
                "3. Try any protected route — the `Authorization: Bearer …` header is sent automatically.\n\n"
                "Default admin: `admin@cybersentinel.local` / `admin123`"
            ),
            routes=app.routes,
        )

        schema.setdefault("components", {})
        schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": (
                    "JWT from POST /api/v1/auth/token. Paste only the access_token value "
                    "(Swagger adds the Bearer prefix)."
                ),
            },
        }

        for path, path_item in schema.get("paths", {}).items():
            if not path.startswith("/api/v1/"):
                continue
            if path in _AUTH_PUBLIC_PATHS:
                for operation in path_item.values():
                    if isinstance(operation, dict):
                        operation["security"] = []
                continue
            for operation in path_item.values():
                if isinstance(operation, dict):
                    operation["security"] = [{"BearerAuth": []}]

        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
