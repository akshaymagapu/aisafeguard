"""Core data models for AISafe Guard."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Action(str, Enum):
    """Action to take when a scanner detects a violation."""

    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    REDACT = "redact"


class Tier(int, Enum):
    """Scanner performance tier."""

    FAST = 1       # <5ms — regex, rules, pattern matching
    MEDIUM = 2     # 20-50ms — ML classifiers, local models
    SLOW = 3       # 100-500ms — LLM-as-judge, API calls


class Finding(BaseModel):
    """A single issue found by a scanner."""

    scanner: str = Field(description="Name of the scanner that found this issue")
    category: str = Field(description="Category of the finding (e.g., 'pii', 'injection')")
    severity: str = Field(default="medium", description="Severity: low, medium, high, critical")
    description: str = Field(description="Human-readable description of the finding")
    matched_text: str | None = Field(default=None, description="The text that triggered the finding")
    start: int | None = Field(default=None, description="Start index in the original text")
    end: int | None = Field(default=None, description="End index in the original text")
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result from a single scanner execution."""

    scanner: str = Field(description="Name of the scanner")
    passed: bool = Field(description="Whether the text passed this scanner's checks")
    score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Safety score: 1.0 = safe, 0.0 = unsafe",
    )
    findings: list[Finding] = Field(default_factory=list)
    sanitized: str | None = Field(
        default=None,
        description="Sanitized version of the text (e.g., PII redacted)",
    )
    duration_ms: float = Field(default=0.0, description="Scanner execution time in milliseconds")
    tier: Tier = Field(default=Tier.FAST)


class PipelineResult(BaseModel):
    """Aggregated result from running all scanners in a pipeline."""

    passed: bool = Field(description="Whether all scanners passed")
    results: list[ScanResult] = Field(default_factory=list)
    action_taken: Action = Field(default=Action.LOG)
    sanitized: str | None = Field(
        default=None,
        description="Final sanitized text after all redactions applied",
    )
    total_duration_ms: float = Field(default=0.0)

    @property
    def findings(self) -> list[Finding]:
        """All findings from all scanners."""
        return [f for r in self.results for f in r.findings]

    @property
    def failed_scanners(self) -> list[str]:
        """Names of scanners that failed."""
        return [r.scanner for r in self.results if not r.passed]


class Report(BaseModel):
    """Full report for a single guarded LLM interaction."""

    input_result: PipelineResult | None = Field(default=None)
    output_result: PipelineResult | None = Field(default=None)
    blocked: bool = Field(default=False, description="Whether the interaction was blocked")
    timestamp: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """Whether both input and output passed all checks."""
        input_ok = self.input_result.passed if self.input_result else True
        output_ok = self.output_result.passed if self.output_result else True
        return input_ok and output_ok

    @property
    def all_findings(self) -> list[Finding]:
        """All findings from input and output scans."""
        findings: list[Finding] = []
        if self.input_result:
            findings.extend(self.input_result.findings)
        if self.output_result:
            findings.extend(self.output_result.findings)
        return findings
