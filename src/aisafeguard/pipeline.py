"""Pipeline for chaining scanners with tiered execution."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from aisafeguard.models import Action, PipelineResult, ScanResult, Tier
from aisafeguard.scanners.base import BaseScanner


class Pipeline:
    """Executes an ordered chain of scanners with tiered performance.

    Scanners are grouped by tier and executed in order:
    - Tier 1 (fast): All run first. If any fail with action=block, skip higher tiers.
    - Tier 2 (medium): Run if Tier 1 passed or action != block.
    - Tier 3 (slow): Run only if needed.
    """

    def __init__(
        self,
        scanners: list[BaseScanner] | None = None,
        fail_action: Action = Action.BLOCK,
        fail_fast: bool = True,
        scanner_actions: dict[str, Action] | None = None,
    ) -> None:
        self.scanners = scanners or []
        self.fail_action = fail_action
        self.fail_fast = fail_fast
        self.scanner_actions = scanner_actions or {}

    def add_scanner(self, scanner: BaseScanner) -> None:
        self.scanners.append(scanner)

    async def run(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> PipelineResult:
        """Run all scanners in tiered order."""
        start = time.perf_counter()
        all_results: list[ScanResult] = []
        sanitized = text
        passed = True

        tiers = {
            Tier.FAST: [],
            Tier.MEDIUM: [],
            Tier.SLOW: [],
        }
        for scanner in self.scanners:
            tier = getattr(scanner, "tier", Tier.FAST)
            tiers[tier].append(scanner)

        for tier in [Tier.FAST, Tier.MEDIUM, Tier.SLOW]:
            tier_scanners = tiers[tier]
            if not tier_scanners:
                continue

            if self.fail_fast and all_results and self._resolve_action(all_results) == Action.BLOCK:
                break

            tier_results = await asyncio.gather(
                *[s.execute(sanitized, context) for s in tier_scanners]
            )

            for result in tier_results:
                all_results.append(result)
                if not result.passed:
                    passed = False
                if result.sanitized is not None:
                    sanitized = result.sanitized

        elapsed_ms = (time.perf_counter() - start) * 1000

        action = self._resolve_action(all_results)

        return PipelineResult(
            passed=passed,
            results=all_results,
            action_taken=action,
            sanitized=sanitized if sanitized != text else None,
            total_duration_ms=elapsed_ms,
        )

    def _resolve_action(self, results: list[ScanResult]) -> Action:
        failed_results = [result for result in results if not result.passed]
        if not failed_results:
            return Action.LOG

        # BLOCK > REDACT > WARN > LOG
        rank = {
            Action.LOG: 0,
            Action.WARN: 1,
            Action.REDACT: 2,
            Action.BLOCK: 3,
        }
        selected = Action.LOG
        for result in failed_results:
            action = self.scanner_actions.get(result.scanner, self.fail_action)
            if rank[action] > rank[selected]:
                selected = action
        return selected
