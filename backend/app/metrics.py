"""
In-process metrics registry.

Provides a thin, dependency-free metrics abstraction that can be swapped for
prometheus_client, opentelemetry, or datadog-metrics without changing call
sites.  Until an external metrics backend is configured, counters and
histograms accumulate in memory and are exposed via GET /api/v1/metrics.

Design notes
------------
* Thread-safe: each counter and histogram uses its own ``threading.Lock`` so
  the registry is safe under asyncio + thread-pool executor patterns.
* Intentionally minimal: only Counter and Histogram.  Gauges can be added
  when needed.
* The ``REGISTRY`` singleton is module-level; it is reset between test runs
  by calling ``REGISTRY.reset()``.

Registered metrics
------------------
ingest_requests_total       Counter   Each call to POST /ingest
ingest_errors_total         Counter   Validation errors in ingestion service
normalize_requests_total    Counter   Each call to POST /normalize
normalize_errors_total      Counter   Normalization pipeline failures
normalize_retry_total       Counter   Each call to POST /normalize/{id}/retry
classify_requests_total     Counter   Each call to POST /classify
classify_errors_total       Counter   Classification provider errors
normalization_duration_s    Histogram Wall-clock seconds for normalize_ingestion
segments_per_ingestion      Histogram Segment count produced per normalization run
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Generator


# ---------------------------------------------------------------------------
# Primitive types
# ---------------------------------------------------------------------------


class Counter:
    """Monotonically increasing integer counter."""

    __slots__ = ("_lock", "_value")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: int = 0

    def increment(self, n: int = 1) -> None:
        with self._lock:
            self._value += n

    def get(self) -> int:
        with self._lock:
            return self._value

    def reset(self) -> None:
        with self._lock:
            self._value = 0


class Histogram:
    """
    Records float observations.

    Tracks count, sum, min, and max — sufficient for mean and range without
    storing individual samples.
    """

    __slots__ = ("_lock", "_count", "_sum", "_min", "_max")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count: int = 0
        self._sum: float = 0.0
        self._min: float = float("inf")
        self._max: float = float("-inf")

    def observe(self, value: float) -> None:
        with self._lock:
            self._count += 1
            self._sum += value
            if value < self._min:
                self._min = value
            if value > self._max:
                self._max = value

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "count": self._count,
                "sum": round(self._sum, 6),
                "mean": round(self._sum / self._count, 6) if self._count else 0.0,
                "min": round(self._min, 6) if self._count else None,
                "max": round(self._max, 6) if self._count else None,
            }

    def reset(self) -> None:
        with self._lock:
            self._count = 0
            self._sum = 0.0
            self._min = float("inf")
            self._max = float("-inf")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class MetricsRegistry:
    """
    Central store for all application metrics.

    Usage::

        from backend.app.metrics import REGISTRY

        REGISTRY.increment("ingest_requests_total")
        REGISTRY.observe("normalization_duration_s", elapsed)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}

    # ── Counter operations ────────────────────────────────────────────────────

    def counter(self, name: str) -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter()
            return self._counters[name]

    def increment(self, name: str, n: int = 1) -> None:
        self.counter(name).increment(n)

    # ── Histogram operations ──────────────────────────────────────────────────

    def histogram(self, name: str) -> Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram()
            return self._histograms[name]

    def observe(self, name: str, value: float) -> None:
        self.histogram(name).observe(value)

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = {name: c.get() for name, c in self._counters.items()}
            histograms = {name: h.snapshot() for name, h in self._histograms.items()}
        return {"counters": counters, "histograms": histograms}

    # ── Test helpers ──────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Reset all metrics to zero.  Intended for test isolation only."""
        with self._lock:
            for c in self._counters.values():
                c.reset()
            for h in self._histograms.values():
                h.reset()


REGISTRY: MetricsRegistry = MetricsRegistry()


# ---------------------------------------------------------------------------
# Convenience context manager for timing
# ---------------------------------------------------------------------------


@contextmanager
def timed(histogram_name: str, registry: MetricsRegistry = REGISTRY) -> Generator[None, None, None]:
    """
    Context manager that measures wall-clock time and records it as a
    histogram observation::

        with timed("normalization_duration_s"):
            result = run_normalization_pipeline(...)
    """
    start = time.monotonic()
    try:
        yield
    finally:
        registry.observe(histogram_name, time.monotonic() - start)
