"""Base classes for input and output scanners."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from aisafeguard.models import ScanResult, Tier


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    name: str = "base"
    tier: Tier = Tier.FAST

    def __init__(self, threshold: float = 0.5, **kwargs: Any) -> None:
        self.threshold = threshold
        self._kwargs = kwargs

    async def execute(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        """Execute the scanner and measure timing."""
        start = time.perf_counter()
        result = await self.scan(text, context)
        elapsed_ms = (time.perf_counter() - start) * 1000
        result.duration_ms = elapsed_ms
        result.scanner = self.name
        result.tier = self.tier
        return result

    @abstractmethod
    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        """Scan text and return a result. Subclasses must implement this."""
        ...


class InputScanner(BaseScanner):
    """Scanner that runs on user input before sending to LLM."""
    pass


class OutputScanner(BaseScanner):
    """Scanner that runs on LLM output before returning to user."""
    pass
