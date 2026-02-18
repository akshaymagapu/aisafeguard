# AISafe Guard — Universal AI Safety Toolkit

## Context

AI applications are shipping without adequate safety controls. The OWASP LLM Top 10 lists prompt injection as the #1 vulnerability, 97% of breached AI organizations lack proper access controls, and AI privacy incidents rose 56.4% year-over-year. Existing tools (Guardrails AI, NeMo Guardrails, LLM Guard) each solve part of the problem but none offer a unified, model-agnostic, low-latency, developer-friendly solution that scales from solo dev to enterprise.

**AISafe Guard** fills this gap: an open-core Python library + optional proxy that wraps any LLM call with composable safety checks — prompt injection detection, PII scrubbing, toxicity filtering, hallucination checks, compliance logging — all with <50ms overhead for fast-tier checks.

---

## Project Identity

**Name:** `aisafeguard` (package name: `aisafeguard`, CLI: `aisafe`)
**Tagline:** "Safety rails for every AI app"
**License:** Apache 2.0 (core) + Commercial (enterprise features)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│              Your Application Code               │
│  @guard(checks=["injection", "pii", "toxicity"]) │
│  def ask_llm(prompt): ...                        │
└────────────┬─────────────────────────────────────┘
             │
      ┌──────▼──────────────────────────────────┐
      │         AISafe Guard Core               │
      │  ┌─────────┐ ┌──────────┐ ┌──────────┐ │
      │  │ Input   │ │ Output   │ │ Agent    │ │
      │  │ Scanner │ │ Scanner  │ │ Scanner  │ │
      │  └────┬────┘ └─────┬────┘ └─────┬────┘ │
      │       │             │            │      │
      │  ┌────▼─────────────▼────────────▼────┐ │
      │  │     Validator Pipeline              │ │
      │  │  Tier1: Regex/Rules    (<5ms)       │ │
      │  │  Tier2: ML Classifiers (20-50ms)    │ │
      │  │  Tier3: LLM Judges    (100-500ms)   │ │
      │  └────┬───────────────────────────────┘ │
      │       │                                 │
      │  ┌────▼──────────────────────────────┐  │
      │  │  Policy Engine (YAML + Code)      │  │
      │  │  → block / warn / log / redact    │  │
      │  └────┬──────────────────────────────┘  │
      │       │                                 │
      │  ┌────▼──────────────────────────────┐  │
      │  │  Telemetry (OpenTelemetry)        │  │
      │  │  → traces, metrics, audit logs    │  │
      │  └───────────────────────────────────┘  │
      └─────────────────────────────────────────┘
             │
      ┌──────▼──────────────────────────────────┐
      │  Optional: AISafe Proxy (FastAPI)       │
      │  OpenAI-compatible API gateway          │
      │  Works with ANY language/framework      │
      └─────────────────────────────────────────┘
```

---

## Key Abstractions

| Concept | Description |
|---------|-------------|
| **Guard** | Top-level orchestrator. Wraps an LLM call, runs input scanners before and output scanners after. |
| **Scanner** | A check that runs on text. Returns `ScanResult(passed, score, findings, remediation)`. Two types: `InputScanner` and `OutputScanner`. |
| **Policy** | Rules that determine what to do when a scanner fails: `block`, `warn`, `redact`, `log`. Configurable per-scanner. |
| **Pipeline** | An ordered chain of scanners. Supports tiered execution (fast checks first, skip slow checks if fast ones pass). |
| **Report** | Structured output of all scanner results, timings, and policy decisions for a single LLM interaction. |

---

## Phase 1 — MVP (Core Library)

### Goal
A pip-installable library that wraps any LLM call with safety checks. Zero-config defaults that work, YAML config for customization.

### 1.1 Core Scanners (8 built-in)

**Input Scanners:**
| Scanner | Tier | Method | Description |
|---------|------|--------|-------------|
| `PromptInjection` | 1+2 | Regex heuristics + small classifier model | Detects direct/indirect prompt injection attempts |
| `Jailbreak` | 2 | ML classifier (DeBERTa-based) | Detects jailbreak patterns (DAN, roleplay, etc.) |
| `PIIInput` | 1 | Regex + spaCy NER | Detects PII in user prompts before sending to LLM |
| `TopicBan` | 1 | Keyword + embedding similarity | Restricts prompts to allowed topics |

**Output Scanners:**
| Scanner | Tier | Method | Description |
|---------|------|--------|-------------|
| `PIIOutput` | 1 | Regex + spaCy NER | Detects/redacts PII in LLM responses |
| `Toxicity` | 2 | ML classifier (detoxify) | Scores toxicity, hate, threat, insult |
| `Relevance` | 2 | Embedding similarity | Checks if response is relevant to the prompt |
| `MaliciousURL` | 1 | URL extraction + blocklist | Detects known malicious URLs in output |

### 1.2 API Design

**Pattern 1: Decorator (simplest)**
```python
from aisafeguard import guard

@guard(input=["prompt_injection", "pii"], output=["toxicity", "pii"])
async def ask(prompt: str, model: str = "gpt-4") -> str:
    return await openai.chat(model=model, messages=[{"role": "user", "content": prompt}])

result = await ask("What is John's SSN?")
```

**Pattern 2: Context Manager (more control)**
```python
from aisafeguard import Guard

async with Guard(config="aisafe.yaml") as g:
    input_result = await g.scan_input(user_prompt)
    if not input_result.passed:
        print(f"Blocked: {input_result.findings}")
        return

    response = await openai.chat(messages=[{"role": "user", "content": user_prompt}])

    output_result = await g.scan_output(response.content, context=user_prompt)
    if not output_result.passed:
        response = output_result.sanitized
```

**Pattern 3: Wrap any LLM provider (zero-change integration)**
```python
from aisafeguard import Guard
from aisafeguard.integrations import wrap_openai
import openai

client = wrap_openai(openai.AsyncOpenAI(), guard=Guard(config="aisafe.yaml"))

response = await client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}]
)
```

### 1.3 YAML Configuration

```yaml
# aisafe.yaml
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
  jailbreak:
    enabled: true
    threshold: 0.85
    action: block

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
```

### 1.4 Install Tiers
```bash
pip install aisafeguard                    # Core: regex scanners, PII, config, CLI (~5 deps)
pip install aisafeguard[ml]                # + ML classifiers (toxicity, jailbreak, injection)
pip install aisafeguard[proxy]             # + FastAPI proxy server
pip install aisafeguard[integrations]      # + LangChain, LiteLLM wrappers
pip install aisafeguard[all]               # Everything
```

---

## Phase 2 — Proxy + Integrations + Dashboard

### 2.1 Proxy / Gateway Mode
- FastAPI server with OpenAI-compatible `/v1/chat/completions` endpoint
- Forwards to any upstream LLM (OpenAI, Anthropic, Ollama, vLLM, etc.)
- Rate limiting, cost tracking, per-user policies
- Docker image for easy deployment

### 2.2 Web Dashboard (Open-Core)
- **Free tier:** Real-time log viewer, scanner results, basic metrics
- **Premium tier:** Analytics, trend charts, compliance reports, team management

### 2.3 Additional Scanners
- `HallucinationCheck`, `BiasDetection`, `CodeSecurity`, `CopyrightCheck`, `LanguageDetection`, `SensitiveTopics`

### 2.4 Framework Integrations
- LangChain / LangGraph, LiteLLM, Vercel AI SDK, Haystack, CrewAI / AutoGen

---

## Phase 3 — Enterprise (Premium)

### 3.1 Compliance Module
- GDPR, HIPAA, SOC2, EU AI Act, PCI-DSS profiles
- Audit trail generation, data residency controls

### 3.2 Red-Team Testing Framework
- 500+ adversarial test cases
- CI/CD integration (`aisafe redteam` in GitHub Actions)

### 3.3 Team & Policy Management
- RBAC, shared policy repo, approval workflows

### 3.4 Advanced Analytics
- Violation trends, scanner effectiveness, cost analysis
