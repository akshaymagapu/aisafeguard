"""Jailbreak detection scanner."""

from __future__ import annotations

import re
from typing import Any

from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import InputScanner

# Jailbreak patterns — detect known jailbreak techniques
JAILBREAK_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    # DAN (Do Anything Now) variants
    (
        "dan",
        re.compile(
            r"(?i)(?:DAN\s*(?:\d+(?:\.\d+)?)?|do\s+anything\s+now|"
            r"you\s+can\s+do\s+anything\s+now|DANMode)",
        ),
        "DAN jailbreak pattern detected",
        "critical",
    ),
    # Developer/Debug mode
    (
        "developer_mode",
        re.compile(
            r"(?i)(?:developer\s+mode|debug\s+mode|maintenance\s+mode|"
            r"admin\s+mode|sudo\s+mode|root\s+access|enable\s+developer)",
        ),
        "Developer/debug mode jailbreak attempt",
        "high",
    ),
    # Hypothetical/fiction framing
    (
        "hypothetical",
        re.compile(
            r"(?i)(?:hypothetically|in\s+a\s+(?:fictional|imaginary|hypothetical)\s+"
            r"(?:world|scenario|universe)|for\s+(?:a|my)\s+(?:novel|story|book|movie|script)|"
            r"purely\s+(?:academic|educational|research|fictional))\s*[,:]?\s*"
            r"(?:how\s+(?:would|could|can|do)|what\s+(?:would|if))",
        ),
        "Hypothetical framing to bypass safety",
        "medium",
    ),
    # Character/persona adoption
    (
        "persona",
        re.compile(
            r"(?i)(?:from\s+now\s+on|starting\s+now|henceforth)\s*[,:]?\s*"
            r"(?:you\s+(?:are|will\s+be|shall\s+be|must\s+act\s+as)|"
            r"act\s+as\s+(?:if\s+you\s+(?:are|were)|an?\s+(?:evil|unrestricted|unfiltered)))",
        ),
        "Persona adoption jailbreak",
        "high",
    ),
    # Token smuggling / special tokens
    (
        "token_smuggling",
        re.compile(
            r"(?:<\|endoftext\|>|<\|startoftext\|>|<\|padding\|>|"
            r"\[IGNORE\]|\[OVERRIDE\]|\[SYSTEM\]|\[ADMIN\])",
        ),
        "Token smuggling attempt",
        "critical",
    ),
    # Multi-step escalation
    (
        "escalation",
        re.compile(
            r"(?i)(?:first|step\s+1|to\s+begin)[,:]?\s*(?:confirm|acknowledge|agree|say\s+yes)"
            r".*(?:then|next|step\s+2|after\s+that)[,:]?\s*(?:you\s+(?:will|can|should)|"
            r"tell\s+me|provide|give\s+me)",
        ),
        "Multi-step escalation jailbreak",
        "high",
    ),
    # Roleplay/simulation
    (
        "roleplay",
        re.compile(
            r"(?i)(?:let'?s?\s+(?:play|simulate|pretend|roleplay|imagine)|"
            r"we'?re?\s+(?:playing|simulating|role\s*playing)|"
            r"this\s+is\s+(?:a\s+)?(?:simulation|game|roleplay|exercise))\s*"
            r"(?:where|in\s+which)?\s*(?:you\s+(?:are|have|can)|there\s+are\s+no\s+(?:rules|limits))",
        ),
        "Roleplay-based jailbreak attempt",
        "high",
    ),
]


class JailbreakScanner(InputScanner):
    """Detects jailbreak attempts in user input.

    Tier 1: Pattern-based detection of known jailbreak techniques.
    """

    name = "jailbreak"
    tier = Tier.FAST

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings: list[Finding] = []

        for pattern_name, pattern, description, severity in JAILBREAK_PATTERNS:
            matches = list(pattern.finditer(text))
            for match in matches:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category="jailbreak",
                        severity=severity,
                        description=description,
                        matched_text=match.group()[:200],
                        start=match.start(),
                        end=match.end(),
                        metadata={"technique": pattern_name},
                    )
                )

        # Score based on findings
        if not findings:
            score = 1.0
        else:
            # Weight by severity
            severity_weights = {"critical": 0.5, "high": 0.3, "medium": 0.2, "low": 0.1}
            total_weight = sum(
                severity_weights.get(f.severity, 0.2) for f in findings
            )
            score = max(0.0, 1.0 - total_weight)

        passed = score >= self.threshold

        return ScanResult(
            scanner=self.name,
            passed=passed,
            score=score,
            findings=findings,
        )
