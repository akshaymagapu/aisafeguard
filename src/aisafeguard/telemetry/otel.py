"""OpenTelemetry integration for AISafe Guard.

Requires the [telemetry] extra: pip install aisafeguard[telemetry]
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, StatusCode

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False

TRACER_NAME = "aisafeguard"


def get_tracer() -> Any:
    """Get the AISafe Guard OpenTelemetry tracer."""
    if not HAS_OTEL:
        return None
    return trace.get_tracer(TRACER_NAME)


@contextmanager
def guard_span(
    operation: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """Create an OpenTelemetry span for a guard operation.

    Usage:
        with guard_span("scan_input", {"scanner": "pii"}) as span:
            result = await scanner.execute(text)
            span.set_attribute("passed", result.passed)
    """
    if not HAS_OTEL:
        yield None
        return

    tracer = get_tracer()
    with tracer.start_as_current_span(f"aisafeguard.{operation}") as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(f"aisafeguard.{key}", value)
        try:
            yield span
        except Exception as e:
            span.set_status(StatusCode.ERROR, str(e))
            span.record_exception(e)
            raise


def record_scan_result(span: Any, result: Any) -> None:
    """Record scan result attributes on a span."""
    if not HAS_OTEL or span is None:
        return
    span.set_attribute("aisafeguard.passed", result.passed)
    span.set_attribute("aisafeguard.score", result.score)
    span.set_attribute("aisafeguard.duration_ms", result.duration_ms)
    span.set_attribute("aisafeguard.findings_count", len(result.findings))
