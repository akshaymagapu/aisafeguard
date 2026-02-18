"""PII (Personally Identifiable Information) scanner."""

from __future__ import annotations

import re
from typing import Any

from aisafeguard.config import ScannerConfig
from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import InputScanner, OutputScanner

# PII patterns — regex-based for Tier 1 speed
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "PHONE": re.compile(
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "SSN": re.compile(
        r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
    ),
    "IP_ADDRESS": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"
    ),
}

REDACTION_MARKER = "[REDACTED]"


def _detect_pii(
    text: str, entities: list[str] | None = None
) -> list[Finding]:
    """Detect PII in text using regex patterns."""
    findings: list[Finding] = []
    patterns = PII_PATTERNS
    if entities:
        patterns = {k: v for k, v in patterns.items() if k in entities}

    for entity_type, pattern in patterns.items():
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    scanner="pii",
                    category="pii",
                    severity="high",
                    description=f"{entity_type} detected",
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    metadata={"entity_type": entity_type},
                )
            )
    return findings


def _redact_pii(text: str, findings: list[Finding]) -> str:
    """Replace detected PII with redaction markers."""
    # Sort findings by position (reverse) to maintain correct indices
    sorted_findings = sorted(findings, key=lambda f: f.start or 0, reverse=True)
    result = text
    for finding in sorted_findings:
        if finding.start is not None and finding.end is not None:
            entity_type = finding.metadata.get("entity_type", "PII")
            result = result[: finding.start] + f"[{entity_type}_REDACTED]" + result[finding.end :]
    return result


class PIIInputScanner(InputScanner):
    """Detects PII in user input before sending to LLM."""

    name = "pii"
    tier = Tier.FAST

    def __init__(self, threshold: float = 0.5, **kwargs: Any) -> None:
        super().__init__(threshold, **kwargs)
        self.entities: list[str] | None = None

    def configure(self, config: ScannerConfig) -> None:
        self.entities = config.entities

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings = _detect_pii(text, self.entities)
        sanitized = _redact_pii(text, findings) if findings else None
        return ScanResult(
            scanner=self.name,
            passed=len(findings) == 0,
            score=1.0 if not findings else max(0.0, 1.0 - len(findings) * 0.2),
            findings=findings,
            sanitized=sanitized,
        )


class PIIOutputScanner(OutputScanner):
    """Detects and redacts PII in LLM output."""

    name = "pii"
    tier = Tier.FAST

    def __init__(self, threshold: float = 0.5, **kwargs: Any) -> None:
        super().__init__(threshold, **kwargs)
        self.entities: list[str] | None = None

    def configure(self, config: ScannerConfig) -> None:
        self.entities = config.entities

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings = _detect_pii(text, self.entities)
        sanitized = _redact_pii(text, findings) if findings else None
        return ScanResult(
            scanner=self.name,
            passed=len(findings) == 0,
            score=1.0 if not findings else max(0.0, 1.0 - len(findings) * 0.2),
            findings=findings,
            sanitized=sanitized,
        )
