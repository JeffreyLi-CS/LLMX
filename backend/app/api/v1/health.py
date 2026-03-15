"""
Health check endpoint.

GET /api/v1/health — lightweight liveness probe.
No database query; suitable for load balancer / container health checks.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.config import get_settings

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    env: str


@router.get("/health", response_model=HealthResponse, include_in_schema=True)
async def health_check() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        version=settings.app_version,
        env=settings.app_env,
    )
