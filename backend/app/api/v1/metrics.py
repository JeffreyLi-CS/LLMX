"""
GET /api/v1/metrics

Returns a JSON snapshot of all in-process metrics counters and histograms.
Requires the X-API-Key header so that operational data is not publicly visible.

In a production deployment this endpoint should be replaced or supplemented by
a proper metrics exporter (Prometheus scrape endpoint, Datadog DogStatsD, etc.)
wired into the MetricsRegistry at startup.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from backend.app.dependencies import RequireAPIKey
from backend.app.metrics import REGISTRY

router = APIRouter(tags=["metrics"])


@router.get(
    "/metrics",
    status_code=status.HTTP_200_OK,
    dependencies=[RequireAPIKey],
    summary="In-process metrics snapshot",
    description=(
        "Returns a point-in-time snapshot of all application metrics as JSON. "
        "Counters are cumulative since last process restart. "
        "Histogram values include count, sum, mean, min, and max."
    ),
)
def get_metrics() -> dict[str, object]:
    return REGISTRY.snapshot()
