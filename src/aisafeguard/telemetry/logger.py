"""Structured JSON logging for AISafe Guard."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from aisafeguard.models import PipelineResult, Report


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "scan_data"):
            log_data["scan"] = record.scan_data
        if record.exc_info and record.exc_info[1]:
            log_data["error"] = str(record.exc_info[1])
        return json.dumps(log_data, default=str)


def setup_logging(level: str = "info", structured: bool = True) -> None:
    """Configure logging for AISafe Guard."""
    logger = logging.getLogger("aisafeguard")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler()
        if structured:
            handler.setFormatter(StructuredFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
        logger.addHandler(handler)


def log_scan_result(
    direction: str,
    result: PipelineResult,
    text_preview: str | None = None,
) -> None:
    """Log a scan result with structured data."""
    logger = logging.getLogger("aisafeguard")
    scan_data = {
        "direction": direction,
        "passed": result.passed,
        "action": result.action_taken.value,
        "duration_ms": round(result.total_duration_ms, 2),
        "scanners_run": len(result.results),
        "findings_count": len(result.findings),
    }
    if not result.passed:
        scan_data["failed_scanners"] = result.failed_scanners
    if text_preview:
        scan_data["text_preview"] = text_preview[:100]

    record = logger.makeRecord(
        name="aisafeguard",
        level=logging.INFO if result.passed else logging.WARNING,
        fn="",
        lno=0,
        msg=f"Scan {direction}: {'PASSED' if result.passed else 'FAILED'}",
        args=(),
        exc_info=None,
    )
    record.scan_data = scan_data  # type: ignore[attr-defined]
    logger.handle(record)


def log_report(report: Report) -> None:
    """Log a full guard report."""
    if report.input_result:
        log_scan_result("input", report.input_result)
    if report.output_result:
        log_scan_result("output", report.output_result)
