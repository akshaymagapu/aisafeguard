"""Prompt injection detection scanner."""

from __future__ import annotations

import re
from typing import Any

from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import InputScanner

# Heuristic patterns for common prompt injection attempts
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # Direct instruction override
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b.*"
            r"(?:previous|above|prior|earlier|all|system)\b.*"
            r"(?:instructions?|prompts?|rules?|guidelines?|constraints?)",
        ),
        "Attempt to override system instructions",
    ),
    # System prompt extraction
    (
        "system_prompt_extraction",
        re.compile(
            r"(?i)(?:reveal|show|display|print|output|repeat|tell me)\b.*"
            r"(?:system\s*prompt|initial\s*prompt|hidden\s*prompt|system\s*message"
            r"|instructions?|original\s*prompt)",
        ),
        "Attempt to extract system prompt",
    ),
    # Role manipulation
    (
        "role_manipulation",
        re.compile(
            r"(?i)(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|"
            r"assume\s+the\s+role|switch\s+to|enter\s+(?:a\s+)?new\s+mode|"
            r"you\s+are\s+(?:a|an)\s+(?:unrestricted|unfiltered|uncensored))",
        ),
        "Attempt to manipulate AI role/persona",
    ),
    # DAN-style jailbreak
    (
        "dan_jailbreak",
        re.compile(
            r"(?i)(?:DAN|do\s+anything\s+now|jailbreak|developer\s+mode|"
            r"god\s+mode|unrestricted\s+mode|no\s+restrictions|without\s+limits)",
        ),
        "DAN-style jailbreak attempt",
    ),
    # Delimiter injection
    (
        "delimiter_injection",
        re.compile(
            r"(?:```|###|---|\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|"
            r"<\|system\|>|<\|user\|>|<\|assistant\|>|<<SYS>>|<</SYS>>)",
        ),
        "Delimiter/token injection attempt",
    ),
    # Encoded/obfuscated instructions
    (
        "encoding_trick",
        re.compile(
            r"(?i)(?:base64|rot13|hex|decode|encode)\s*(?:the\s+following|this|:)",
        ),
        "Possible encoding-based evasion",
    ),
    # Instruction injection markers
    (
        "injection_markers",
        re.compile(
            r"(?i)(?:new\s+instructions?|updated\s+instructions?|"
            r"additional\s+instructions?|real\s+instructions?|"
            r"actual\s+instructions?|true\s+instructions?)",
        ),
        "Injection marker detected",
    ),
]

# Severity scoring: more patterns matched = higher severity
SEVERITY_THRESHOLDS = {
    1: "medium",
    2: "high",
    3: "critical",
}


class PromptInjectionScanner(InputScanner):
    """Detects prompt injection attempts using heuristic patterns.

    Tier 1: Fast regex-based detection (<5ms).
    For ML-based detection (Tier 2), use with the [ml] extra.
    """

    name = "prompt_injection"
    tier = Tier.FAST

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings: list[Finding] = []

        for pattern_name, pattern, description in INJECTION_PATTERNS:
            matches = list(pattern.finditer(text))
            for match in matches:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category="prompt_injection",
                        severity="medium",
                        description=description,
                        matched_text=match.group()[:200],  # Truncate long matches
                        start=match.start(),
                        end=match.end(),
                        metadata={"pattern": pattern_name},
                    )
                )

        # Calculate score based on number of distinct patterns matched
        unique_patterns = len({f.metadata.get("pattern") for f in findings})
        score = max(0.0, 1.0 - unique_patterns * 0.3)

        # Update severity based on total matches
        severity = SEVERITY_THRESHOLDS.get(
            min(unique_patterns, max(SEVERITY_THRESHOLDS.keys())), "medium"
        )
        for finding in findings:
            finding.severity = severity

        # Determine pass/fail based on threshold
        passed = score >= self.threshold

        return ScanResult(
            scanner=self.name,
            passed=passed,
            score=score,
            findings=findings,
        )
