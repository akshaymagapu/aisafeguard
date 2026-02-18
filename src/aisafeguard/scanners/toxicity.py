"""Toxicity detection scanner."""

from __future__ import annotations

import re
from typing import Any

from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import OutputScanner

# Tier 1: Keyword-based toxicity detection (fast, catches obvious cases)
# These patterns cover clearly toxic content. For nuanced detection, use [ml] extra.
TOXICITY_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "violence_threat",
        re.compile(
            r"(?i)\b(?:i\s+will\s+)?(?:kill|murder|destroy|eliminate|hurt|harm|attack|"
            r"assault|shoot|stab|bomb|explode)\s+(?:you|them|everyone|people)\b",
        ),
        "Violent threat detected",
    ),
    (
        "self_harm",
        re.compile(
            r"(?i)\b(?:how\s+to\s+)?(?:kill\s+(?:my|your)self|suicide|self[- ]harm|"
            r"cut\s+(?:my|your)self|end\s+(?:my|your|it\s+all)\s+life)\b",
        ),
        "Self-harm related content",
    ),
    (
        "illegal_instruction",
        re.compile(
            r"(?i)\b(?:how\s+to\s+)?(?:make\s+(?:a\s+)?(?:bomb|explosive|weapon|drug|meth)|"
            r"synthesize\s+(?:drugs?|meth|fentanyl)|hack\s+into|break\s+into)\b",
        ),
        "Instructions for illegal activity",
    ),
    (
        "hate_speech",
        re.compile(
            r"(?i)\b(?:all\s+(?:\w+\s+)?(?:should\s+die|are\s+(?:inferior|subhuman|worthless))|"
            r"(?:death\s+to|exterminate|genocide)\s+(?:all\s+)?\w+)\b",
        ),
        "Hate speech detected",
    ),
    (
        "harassment",
        re.compile(
            r"(?i)\b(?:you\s+(?:are\s+)?(?:worthless|pathetic|disgusting|stupid|idiot|moron)|"
            r"kys|kill\s+yourself)\b",
        ),
        "Harassment detected",
    ),
]


class ToxicityScanner(OutputScanner):
    """Detects toxic content in LLM output.

    Tier 1 (default): Keyword/pattern-based detection for obvious toxic content.
    Tier 2 (with [ml] extra): ML-based detection using detoxify for nuanced scoring.
    """

    name = "toxicity"
    tier = Tier.FAST  # Base implementation is regex-based

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings: list[Finding] = []

        for pattern_name, pattern, description in TOXICITY_PATTERNS:
            matches = list(pattern.finditer(text))
            for match in matches:
                findings.append(
                    Finding(
                        scanner=self.name,
                        category="toxicity",
                        severity="high",
                        description=description,
                        matched_text=match.group()[:200],
                        start=match.start(),
                        end=match.end(),
                        metadata={"subcategory": pattern_name},
                    )
                )

        # Score: 1.0 = clean, lower = more toxic
        unique_categories = len({f.metadata.get("subcategory") for f in findings})
        score = max(0.0, 1.0 - unique_categories * 0.3)

        passed = score >= self.threshold

        return ScanResult(
            scanner=self.name,
            passed=passed,
            score=score,
            findings=findings,
        )
