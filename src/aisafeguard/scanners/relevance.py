"""Relevance scanner — checks if LLM output is relevant to the input."""

from __future__ import annotations

from typing import Any

from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import OutputScanner


class RelevanceScanner(OutputScanner):
    """Checks if LLM output is relevant to the input prompt.

    Tier 1 (default): Basic keyword overlap check.
    Tier 2 (with [ml] extra): Embedding-based semantic similarity.

    Requires context["input_text"] to be set for comparison.
    """

    name = "relevance"
    tier = Tier.FAST

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        if not context or "input_text" not in context:
            # Can't check relevance without input context
            return ScanResult(scanner=self.name, passed=True, score=1.0)

        input_text = context["input_text"]

        # Basic keyword overlap relevance (Tier 1)
        score = _keyword_overlap(input_text, text)
        passed = score >= self.threshold

        findings: list[Finding] = []
        if not passed:
            findings.append(
                Finding(
                    scanner=self.name,
                    category="relevance",
                    severity="low",
                    description=f"Low relevance score ({score:.2f}) — output may not address the input",
                    metadata={"relevance_score": score},
                )
            )

        return ScanResult(
            scanner=self.name,
            passed=passed,
            score=score,
            findings=findings,
        )


def _keyword_overlap(input_text: str, output_text: str) -> float:
    """Calculate keyword overlap between input and output as a relevance proxy."""
    # Tokenize (simple whitespace split, lowercase, filter short words)
    input_words = {
        w.lower().strip(".,!?;:\"'()[]{}") for w in input_text.split() if len(w) > 2
    }
    output_words = {
        w.lower().strip(".,!?;:\"'()[]{}") for w in output_text.split() if len(w) > 2
    }

    if not input_words:
        return 1.0  # No meaningful input words to compare

    # Filter common stop words
    stop_words = {
        "the", "is", "at", "which", "on", "a", "an", "and", "or", "but",
        "in", "with", "to", "for", "of", "not", "no", "can", "had", "has",
        "have", "was", "were", "been", "will", "would", "could", "should",
        "may", "might", "shall", "do", "does", "did", "are", "this", "that",
        "these", "those", "it", "its", "my", "your", "his", "her", "our",
        "their", "what", "how", "why", "when", "where", "who", "whom",
        "you", "me", "him", "them", "about", "from", "into", "than",
    }
    input_words -= stop_words
    output_words -= stop_words

    if not input_words:
        return 1.0

    overlap = input_words & output_words
    return len(overlap) / len(input_words)
