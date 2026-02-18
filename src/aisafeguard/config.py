"""YAML configuration loader with Pydantic validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from aisafeguard.models import Action


class ScannerConfig(BaseModel):
    """Configuration for a single scanner."""

    enabled: bool = True
    threshold: float = 0.5
    action: Action = Action.BLOCK
    entities: list[str] | None = None
    banned_topics: list[str] | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class SettingsConfig(BaseModel):
    """Global settings."""

    fail_action: Action = Action.BLOCK
    log_level: str = "info"
    telemetry: bool = True


class GuardConfig(BaseModel):
    """Full guard configuration loaded from YAML."""

    version: str = "1"
    settings: SettingsConfig = Field(default_factory=SettingsConfig)
    input: dict[str, ScannerConfig] = Field(default_factory=dict)
    output: dict[str, ScannerConfig] = Field(default_factory=dict)


def load_config(path: str | Path) -> GuardConfig:
    """Load guard configuration from a YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if raw is None:
        return GuardConfig()

    return GuardConfig(**raw)


def get_default_config() -> GuardConfig:
    """Return sensible default configuration."""
    return GuardConfig(
        settings=SettingsConfig(),
        input={
            "prompt_injection": ScannerConfig(enabled=True, threshold=0.8, action=Action.BLOCK),
            "pii": ScannerConfig(
                enabled=True,
                action=Action.REDACT,
                entities=["EMAIL", "PHONE", "SSN", "CREDIT_CARD"],
            ),
        },
        output={
            "toxicity": ScannerConfig(enabled=True, threshold=0.7, action=Action.BLOCK),
            "pii": ScannerConfig(
                enabled=True,
                action=Action.REDACT,
                entities=["EMAIL", "PHONE", "SSN", "CREDIT_CARD"],
            ),
            "malicious_url": ScannerConfig(enabled=True, action=Action.BLOCK),
        },
    )


DEFAULT_YAML = """\
# AISafe Guard Configuration
version: "1"

settings:
  fail_action: block
  log_level: info
  telemetry: true

input:
  prompt_injection:
    enabled: true
    threshold: 0.8
    action: block
  pii:
    enabled: true
    entities: [EMAIL, PHONE, SSN, CREDIT_CARD]
    action: redact

output:
  toxicity:
    enabled: true
    threshold: 0.7
    action: block
  pii:
    enabled: true
    entities: [EMAIL, PHONE, SSN, CREDIT_CARD]
    action: redact
  malicious_url:
    enabled: true
    action: block
"""
