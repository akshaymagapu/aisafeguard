"""Policy engine — determines actions based on scan results."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from aisafeguard.models import Action, PipelineResult

logger = logging.getLogger("aisafeguard")


class PolicyViolation(Exception):
    """Raised when a policy blocks a request."""

    def __init__(self, result: PipelineResult, message: str = "Request blocked by safety policy"):
        self.result = result
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class PolicyDecision:
    """Normalized policy decision for a scan result."""

    action: Action
    blocked: bool
    sanitized: str | None = None


class PolicyEngine:
    """Evaluates pipeline results and enforces actions."""

    def __init__(self, default_action: Action = Action.BLOCK) -> None:
        self.default_action = default_action
        self._action_overrides: dict[str, Action] = {}

    def set_scanner_action(self, scanner_name: str, action: Action) -> None:
        """Override the action for a specific scanner."""
        self._action_overrides[scanner_name] = action

    def get_action(self, scanner_name: str) -> Action:
        """Get the action for a scanner (override or default)."""
        return self._action_overrides.get(scanner_name, self.default_action)

    def enforce(self, result: PipelineResult, context: dict[str, Any] | None = None) -> str | None:
        """Enforce policy on a pipeline result.

        Returns the sanitized text if action is REDACT, None otherwise.
        Raises PolicyViolation if action is BLOCK and the result failed.
        """
        decision = self.decide(result)

        if decision.action == Action.WARN:
            logger.warning(
                "Policy WARN: %d findings from %s",
                len(result.findings),
                result.failed_scanners,
            )

        if decision.action == Action.REDACT:
            logger.info("Policy REDACT: returning sanitized text")
            return decision.sanitized

        if decision.blocked:
            failed = result.failed_scanners
            msg = f"Blocked by scanners: {', '.join(failed)}"
            logger.warning("Policy BLOCK: %s", msg)
            raise PolicyViolation(result, msg)

        # LOG action
        logger.info(
            "Policy LOG: %d findings from %s",
            len(result.findings),
            result.failed_scanners,
        )
        return None

    def decide(self, result: PipelineResult) -> PolicyDecision:
        """Compute a normalized policy decision for a pipeline result."""
        if result.passed:
            return PolicyDecision(action=Action.LOG, blocked=False)

        action = result.action_taken

        # Respect scanner overrides in case callers inject a custom pipeline.
        for scan_result in result.results:
            if not scan_result.passed:
                scanner_action = self.get_action(scan_result.scanner)
                if scanner_action == Action.BLOCK:
                    action = Action.BLOCK
                    break

        return PolicyDecision(
            action=action,
            blocked=action == Action.BLOCK,
            sanitized=result.sanitized if action == Action.REDACT else None,
        )
