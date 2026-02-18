"""Topic ban scanner — restricts prompts to allowed topics."""

from __future__ import annotations

import re
from typing import Any

from aisafeguard.config import ScannerConfig
from aisafeguard.models import Finding, ScanResult, Tier
from aisafeguard.scanners.base import InputScanner

# Default topic keyword maps
TOPIC_KEYWORDS: dict[str, list[str]] = {
    "violence": [
        "kill", "murder", "attack", "weapon", "gun", "bomb", "assault",
        "shoot", "stab", "hurt", "harm", "violent", "torture",
    ],
    "illegal_activity": [
        "hack", "steal", "fraud", "counterfeit", "launder", "smuggle",
        "traffic", "bribe", "forge", "pirate", "extort",
    ],
    "adult_content": [
        "explicit", "nsfw", "pornograph", "sexual",
    ],
    "drugs": [
        "cocaine", "heroin", "meth", "fentanyl", "mdma", "lsd",
        "synthesize drugs", "make drugs", "cook meth",
    ],
    "gambling": [
        "gamble", "betting", "casino", "wager", "slot machine",
    ],
}


class TopicBanScanner(InputScanner):
    """Restricts prompts by detecting banned topics.

    Configure via YAML:
        topic_ban:
          enabled: true
          banned_topics: ["violence", "illegal_activity"]
    """

    name = "topic_ban"
    tier = Tier.FAST

    def __init__(self, threshold: float = 0.5, **kwargs: Any) -> None:
        super().__init__(threshold, **kwargs)
        self.banned_topics: list[str] = []
        self._custom_keywords: dict[str, list[str]] = {}

    def configure(self, config: ScannerConfig) -> None:
        self.banned_topics = config.banned_topics or []

    def add_topic(self, topic: str, keywords: list[str]) -> None:
        """Add a custom topic with keywords."""
        self._custom_keywords[topic] = keywords

    async def scan(self, text: str, context: dict[str, Any] | None = None) -> ScanResult:
        findings: list[Finding] = []
        text_lower = text.lower()

        all_keywords = {**TOPIC_KEYWORDS, **self._custom_keywords}

        for topic in self.banned_topics:
            keywords = all_keywords.get(topic, [])
            for keyword in keywords:
                pattern = re.compile(r"\b" + re.escape(keyword) + r"\b", re.IGNORECASE)
                matches = list(pattern.finditer(text))
                for match in matches:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            category="topic_ban",
                            severity="medium",
                            description=f"Banned topic detected: {topic}",
                            matched_text=match.group(),
                            start=match.start(),
                            end=match.end(),
                            metadata={"topic": topic, "keyword": keyword},
                        )
                    )

        # Deduplicate by topic (one finding per topic is enough)
        seen_topics: set[str] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            topic = f.metadata.get("topic", "")
            if topic not in seen_topics:
                seen_topics.add(topic)
                unique_findings.append(f)

        score = 1.0 if not unique_findings else max(0.0, 1.0 - len(unique_findings) * 0.4)
        passed = len(unique_findings) == 0

        return ScanResult(
            scanner=self.name,
            passed=passed,
            score=score,
            findings=unique_findings,
        )
