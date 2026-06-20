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
from core.security import enforce_read_only_analyst, require_role, resolve_api_role
from db.database import check_database, create_tables, engine
from models.loader import ModelRegistry
from routers.copilot import router as copilot_router
from routers.dashboard import router as dashboard_router
from routers.firewall import router as firewall_router
from routers.intel import router as intel_router
from routers.packet import router as packet_router
from routers.capture import router as capture_router
from routers.reports import router as reports_router
from routers.response import router as response_router
from routers.threat import router as threat_router
from services.packet_capture_service import set_background_event_loop


STARTED_AT = monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting {name} v{version}", name=settings.APP_NAME, version=settings.APP_VERSION)
    set_background_event_loop(asyncio.get_running_loop())
    await create_tables()
    app.state.models = await ModelRegistry.load()
    yield
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


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


@app.middleware("http")
async def api_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/v1"):
        if not settings.API_KEY:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"success": False, "detail": "API key is not configured."},
            )
        role = resolve_api_role(
            request.headers.get("X-API-Key"),
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
                content={"success": False, "detail": "Invalid or missing API key. Use header: X-API-Key: your-api-key"},
            )
        request.state.auth_role = role
    response = await call_next(request)
    return response


@app.middleware("http")
async def production_safety_middleware(request: Request, call_next):
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
