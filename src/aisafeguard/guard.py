"""Guard — main orchestrator for AISafe Guard."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from aisafeguard.config import GuardConfig, get_default_config, load_config
from aisafeguard.models import Action, PipelineResult, Report
from aisafeguard.pipeline import Pipeline
from aisafeguard.policy import PolicyEngine
from aisafeguard.scanners.base import InputScanner, OutputScanner

logger = logging.getLogger("aisafeguard")

# Scanner registry — maps scanner names to classes
_INPUT_SCANNERS: dict[str, type[InputScanner]] = {}
_OUTPUT_SCANNERS: dict[str, type[OutputScanner]] = {}


def register_input_scanner(name: str, cls: type[InputScanner]) -> None:
    _INPUT_SCANNERS[name] = cls


def register_output_scanner(name: str, cls: type[OutputScanner]) -> None:
    _OUTPUT_SCANNERS[name] = cls


def _build_input_pipeline(config: GuardConfig) -> Pipeline:
    """Build the input scanner pipeline from config."""
    scanners: list[InputScanner] = []
    for name, scanner_config in config.input.items():
        if not scanner_config.enabled:
            continue
        cls = _INPUT_SCANNERS.get(name)
        if cls is None:
            logger.warning("Unknown input scanner: %s (skipping)", name)
            continue
        scanner = cls(threshold=scanner_config.threshold)
        if hasattr(scanner, "configure"):
            scanner.configure(scanner_config)
        scanners.append(scanner)
    scanner_actions = {
        name: scanner_config.action
        for name, scanner_config in config.input.items()
        if scanner_config.enabled
    }
    return Pipeline(
        scanners=scanners,
        fail_action=config.settings.fail_action,
        scanner_actions=scanner_actions,
    )


def _build_output_pipeline(config: GuardConfig) -> Pipeline:
    """Build the output scanner pipeline from config."""
    scanners: list[OutputScanner] = []
    for name, scanner_config in config.output.items():
        if not scanner_config.enabled:
            continue
        cls = _OUTPUT_SCANNERS.get(name)
        if cls is None:
            logger.warning("Unknown output scanner: %s (skipping)", name)
            continue
        scanner = cls(threshold=scanner_config.threshold)
        if hasattr(scanner, "configure"):
            scanner.configure(scanner_config)
        scanners.append(scanner)
    scanner_actions = {
        name: scanner_config.action
        for name, scanner_config in config.output.items()
        if scanner_config.enabled
    }
    return Pipeline(
        scanners=scanners,
        fail_action=config.settings.fail_action,
        scanner_actions=scanner_actions,
    )


class Guard:
    """Main orchestrator that runs input/output scanning pipelines.

    Usage:
        # With config file
        guard = Guard(config="aisafe.yaml")

        # With default config
        guard = Guard()

        # Scan input
        result = await guard.scan_input("user prompt")

        # Scan output
        result = await guard.scan_output("llm response", context="user prompt")

        # Full guard (input + output)
        report = await guard.run(input_text="prompt", output_text="response")
    """

    def __init__(
        self,
        config: str | Path | GuardConfig | None = None,
        input_scanners: list[InputScanner] | None = None,
        output_scanners: list[OutputScanner] | None = None,
    ) -> None:
        # Load config
        if isinstance(config, (str, Path)):
            self._config = load_config(config)
        elif isinstance(config, GuardConfig):
            self._config = config
        else:
            self._config = get_default_config()

        # Build pipelines
        if input_scanners is not None:
            input_actions = {
                scanner.name: self._config.input.get(scanner.name, None).action
                if self._config.input.get(scanner.name)
                else self._config.settings.fail_action
                for scanner in input_scanners
            }
            self._input_pipeline = Pipeline(
                scanners=input_scanners,
                fail_action=self._config.settings.fail_action,
                scanner_actions=input_actions,
            )
        else:
            self._input_pipeline = _build_input_pipeline(self._config)

        if output_scanners is not None:
            output_actions = {
                scanner.name: self._config.output.get(scanner.name, None).action
                if self._config.output.get(scanner.name)
                else self._config.settings.fail_action
                for scanner in output_scanners
            }
            self._output_pipeline = Pipeline(
                scanners=output_scanners,
                fail_action=self._config.settings.fail_action,
                scanner_actions=output_actions,
            )
        else:
            self._output_pipeline = _build_output_pipeline(self._config)

        self._policy = PolicyEngine(default_action=self._config.settings.fail_action)

        # Apply per-scanner action overrides from config
        for name, sc in self._config.input.items():
            self._policy.set_scanner_action(name, sc.action)
        for name, sc in self._config.output.items():
            self._policy.set_scanner_action(name, sc.action)

    @property
    def config(self) -> GuardConfig:
        return self._config

    def add_input_scanner(self, scanner: InputScanner) -> None:
        """Add a custom input scanner."""
        self._input_pipeline.add_scanner(scanner)

    def add_output_scanner(self, scanner: OutputScanner) -> None:
        """Add a custom output scanner."""
        self._output_pipeline.add_scanner(scanner)

    async def scan_input(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> PipelineResult:
        """Scan input text through the input pipeline."""
        result = await self._input_pipeline.run(text, context)
        logger.debug(
            "Input scan: passed=%s, scanners=%d, duration=%.1fms",
            result.passed,
            len(result.results),
            result.total_duration_ms,
        )
        return result

    async def scan_output(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> PipelineResult:
        """Scan output text through the output pipeline."""
        result = await self._output_pipeline.run(text, context)
        logger.debug(
            "Output scan: passed=%s, scanners=%d, duration=%.1fms",
            result.passed,
            len(result.results),
            result.total_duration_ms,
        )
        return result

    async def run(
        self,
        input_text: str | None = None,
        output_text: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> Report:
        """Run full guard: scan input and/or output, return a report."""
        report = Report()

        if input_text is not None:
            report.input_result = await self.scan_input(input_text, context)
            if not report.input_result.passed:
                if report.input_result.action_taken == Action.BLOCK:
                    report.blocked = True
                    return report

        if output_text is not None:
            ctx = context or {}
            if input_text:
                ctx["input_text"] = input_text
            report.output_result = await self.scan_output(output_text, ctx)
            if not report.output_result.passed:
                if report.output_result.action_taken == Action.BLOCK:
                    report.blocked = True

        return report

    async def __aenter__(self) -> Guard:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass
