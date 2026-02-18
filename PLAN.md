# AISafe Guard Public Roadmap

This document is the public OSS roadmap for `aisafeguard`.

It focuses on open-source scope, contributor priorities, and release readiness.

## Project Scope (OSS)

- Python package: `aisafeguard`
- CLI: `aisafe`
- OpenAI-compatible proxy mode
- Built-in safety scanners for common LLM risks
- Config-driven policy engine (`block`, `warn`, `log`, `redact`)
- CI/CD and PyPI publishing

## Current Status

### Shipped

- Core architecture (`Guard`, pipelines, scanner abstractions, policy engine)
- Built-in scanners:
  - `prompt_injection`
  - `jailbreak`
  - `pii` (input/output)
  - `toxicity`
  - `malicious_url`
  - `topic_ban`
  - `relevance`
- YAML configuration + defaults
- Decorator API (`@guard`)
- Provider wrappers:
  - `wrap_openai`
  - `wrap_anthropic`
- CLI commands:
  - `init`
  - `scan`
  - `validate`
  - `proxy`
  - `redteam`
- OpenTelemetry hooks + structured logging
- Proxy forwarding with policy checks
- Dockerfile, tests, benchmarks, GitHub workflows

### In Progress

- Documentation hardening (usage examples, troubleshooting, integration guides)
- Expanded scanner test corpus and red-team prompts
- Proxy performance and reliability tuning

### Planned

- Additional scanners (hallucination, bias, code security)
- More provider/framework integrations
- Better benchmark reporting and performance baselines
- Extended policy presets for common use cases

## Milestones

### Milestone A: Core Stability

Goal: Keep OSS core reliable and predictable for production use.

- Maintain green CI and release quality checks
- Improve scanner precision/recall on curated test sets
- Expand regression tests for policy and proxy behavior

### Milestone B: Ecosystem Integrations

Goal: Reduce adoption friction in existing AI stacks.

- Improve wrapper compatibility across SDK versions
- Add practical framework examples
- Add stronger proxy interoperability tests

### Milestone C: Performance and Operations

Goal: Support higher traffic and better observability.

- Tiered scan latency tracking in benchmarks
- Better proxy error handling and metrics
- Operational runbooks and deployment guides

## Contribution Priorities

Good first contribution areas:

- Scanner test cases and false-positive tuning
- Documentation examples for common app patterns
- CLI UX improvements
- Proxy reliability and edge-case handling
- Integration tests for wrappers and proxy contracts

## Release Model

- PyPI publish is tag-driven (`vX.Y.Z`) via GitHub Actions
- Conventional commits are used for changelog/version automation
- Main branch is protected and uses PR-based merges

## Notes

- This roadmap intentionally excludes private/commercial planning details.
- Public issues and PRs should align with the OSS scope listed above.
