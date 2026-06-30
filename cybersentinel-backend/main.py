"""
CyberSentinel FastAPI application.

This file wires the backend together: startup lifecycle, database creation,
ML model loading, CORS, routers, and health/admin endpoints.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from collections import defaultdict, deque
from time import monotonic
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from loguru import logger

from core.config import settings
from core.openapi import configure_openapi
from core.security import enforce_read_only_analyst, require_role, resolve_request_role
from services.auth_service import decode_access_token
from db.database import AsyncSessionLocal, check_database, create_tables, engine
from models.loader import ModelRegistry
from routers.auth import router as auth_router
from routers.copilot import router as copilot_router
from routers.dashboard import router as dashboard_router
from routers.firewall import router as firewall_router
from routers.intel import router as intel_router
from routers.packet import router as packet_router
from routers.capture import router as capture_router
from routers.reports import router as reports_router
from routers.response import router as response_router
from routers.threat import router as threat_router
from services.auth_service import ensure_default_admin
from services.packet_capture_service import set_background_event_loop


STARTED_AT = monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting {name} v{version}", name=settings.APP_NAME, version=settings.APP_VERSION)
    logger.info(
        "Database: {provider} ({url})",
        provider=settings.database_provider,
        url=settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else "configured",
    )
    if settings.database_provider == "sqlite":
        logger.warning("SQLite is only allowed for automated tests — use Supabase in production.")
    set_background_event_loop(asyncio.get_running_loop())
    await create_tables()
    async with AsyncSessionLocal() as session:
        await ensure_default_admin(session)
    if settings.email_configured:
        logger.info(
            "Password reset email enabled via {provider} (from {from_email})",
            provider=settings.email_provider,
            from_email=settings.SMTP_FROM_EMAIL,
        )
    else:
        logger.error(
            "Password reset email is NOT configured. Add RESEND_API_KEY or SMTP_* to .env "
            "before using POST /api/v1/auth/forgot-password."
        )

    # Empty registry so /health responds before heavy ML artifacts finish loading.
    app.state.models = ModelRegistry()

    async def _load_models() -> None:
        try:
            app.state.models = await ModelRegistry.load()
        except Exception as exc:
            logger.error("Background ML model load failed: {error}", error=exc)

    model_task = asyncio.create_task(_load_models())
    yield
    model_task.cancel()
    try:
        await model_task
    except asyncio.CancelledError:
        pass
    logger.info("Shutting down {name}", name=settings.APP_NAME)
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
configure_openapi(app)


_rate_limit_buckets: dict[str, deque[float]] = defaultdict(deque)
PUBLIC_PATHS = {
    "/",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/meta.json",
    "/favicon.ico",
}


AUTH_PUBLIC_ROUTES = {
    ("POST", "/api/v1/auth/token"),
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/forgot-password"),
    ("POST", "/api/v1/auth/reset-password"),
    ("GET", "/api/v1/auth/reset-password/validate"),
}


@app.middleware("http")
async def api_auth_middleware(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS":
        return await call_next(request)

    if path.startswith("/api/v1"):
        if (request.method, path) in AUTH_PUBLIC_ROUTES:
            return await call_next(request)

        role = resolve_request_role(
            request.headers.get("X-API-Key") if settings.USE_API_KEY_AUTH else None,
            request.headers.get("Authorization"),
        )
        if role is None:
            client_ip = request.client.host if request.client else "unknown"
            logger.warning(
                "Unauthorized API access from {ip} {method} {path}",
                ip=client_ip,
                method=request.method,
                path=path,
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "success": False,
                    "detail": (
                        "Authentication required. Register at POST /api/v1/auth/register, "
                        "login at POST /api/v1/auth/token, then send Authorization: Bearer <token>."
                    ),
                },
            )
        request.state.auth_role = role
        authorization = request.headers.get("Authorization")
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
            payload = decode_access_token(token)
            if payload and payload.get("sub"):
                request.state.user_id = str(payload["sub"])

    response = await call_next(request)
    return response


@app.middleware("http")
async def production_safety_middleware(request: Request, call_next):
    if settings.RATE_LIMIT_PER_MINUTE > 0:
        client_ip = request.client.host if request.client else "unknown"
        now = monotonic()
        bucket = _rate_limit_buckets[client_ip]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= settings.RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"success": False, "detail": "Too many requests. Please retry shortly."},
            )
        bucket.append(now)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# Register CORS last so it runs first and handles browser preflight (OPTIONS)
# before the API-key middleware below.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


app.include_router(auth_router)
app.include_router(packet_router)
app.include_router(firewall_router)
app.include_router(capture_router)
app.include_router(threat_router)
app.include_router(intel_router)
app.include_router(dashboard_router)
app.include_router(response_router)
app.include_router(copilot_router)
app.include_router(reports_router)


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "detail": exc.detail},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled error on {method} {path}", method=request.method, path=request.url.path)
    detail = str(exc) if settings.DEBUG else "Internal server error"
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"success": False, "detail": detail},
    )


@app.get("/", tags=["System"])
async def root() -> dict[str, Any]:
    return {
        "success": True,
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
        "docs": "/docs",
    }


@app.get("/meta.json", include_in_schema=False)
async def meta_json() -> dict[str, Any]:
    return {
        "success": True,
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/health", tags=["System"])
async def health(request: Request) -> dict[str, Any]:
    models: ModelRegistry = request.app.state.models
    try:
        database_ok = await check_database()
    except Exception as exc:
        logger.warning("Database health check failed: {}", exc)
        database_ok = False
    return {
        "success": True,
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "uptime_seconds": round(monotonic() - STARTED_AT, 2),
        "database": "ok" if database_ok else "unavailable",
        "database_provider": settings.database_provider,
        "auth": "jwt",
        "public_signup": settings.ALLOW_PUBLIC_SIGNUP,
        "models": {
            "packet_classifier": {
                "available": models.packet_classifier_available,
                "metadata": models.packet_classifier_meta,
                "path": str(settings.SUPERVISED_MODEL_DIR),
            },
            "packet_anomaly_detector": {
                "available": models.packet_anomaly_available,
                "metadata": models.packet_anomaly_meta,
                "path": str(settings.packet_anomaly_model_path),
            },
            "firewall_pipeline": {
                "available": models.firewall_pipeline_available,
                "metadata": models.firewall_pipeline_meta,
                "path": str(settings.UNSUPERVISED_MODEL_DIR),
            },
        },
    }


@app.post(
    "/api/v1/admin/reload-models",
    tags=["Admin"],
    dependencies=[Depends(require_role("admin"))],
)
async def reload_models(request: Request) -> dict[str, Any]:
    models: ModelRegistry = request.app.state.models
    await models.reload()
    return {
        "success": True,
        "packet_classifier_available": models.packet_classifier_available,
        "packet_anomaly_available": models.packet_anomaly_available,
        "firewall_pipeline_available": models.firewall_pipeline_available,
    }
