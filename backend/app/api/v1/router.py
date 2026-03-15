"""
API v1 router — aggregates all v1 sub-routers.
"""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1 import health, ingestion, normalization

api_v1_router = APIRouter()

api_v1_router.include_router(health.router)
api_v1_router.include_router(ingestion.router)
api_v1_router.include_router(normalization.router)
