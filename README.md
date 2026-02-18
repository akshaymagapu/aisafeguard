# AISafe Guard

`aisafeguard` is an open-source LLM safety and guardrails toolkit for AI apps.

It helps protect against prompt injection, jailbreak attempts, PII leaks, toxic output, and malicious URLs with a Python SDK, CLI, and OpenAI-compatible proxy.

## Why AISafe Guard

- Add AI safety checks to any LLM app with minimal code changes
- Enforce configurable guardrail policies: `block`, `warn`, `log`, `redact`
- Protect both input prompts and model outputs
- Use as a library or as a language-agnostic proxy gateway

## Core Features

- Prompt injection detection
- Jailbreak detection
- PII detection and redaction
- Toxicity filtering
- Malicious URL detection
- Relevance checks
- OpenAI/Anthropic wrappers
- OpenAI-compatible proxy mode

## Install

```bash
pip install aisafeguard
```

From source (fresh clone):

```bash
pip install .
```

Optional extras:

```bash
pip install "aisafeguard[ml]"
pip install "aisafeguard[proxy]"
pip install "aisafeguard[integrations]"
pip install "aisafeguard[telemetry]"
```

## Repository Setup

```bash
git clone <your-repo-url>
cd aisafeguard
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
npm install
```

## Node.js Users

This repo does not currently ship a native Node SDK package for runtime usage.

Recommended Node integration today:
1. Run `aisafe proxy` (or Docker) from this repo.
2. Call the OpenAI-compatible endpoint from your Node app.
3. Keep safety policy/config centralized in `aisafe.yaml`.

Example (Node fetch):

```js
const res = await fetch("http://localhost:8000/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json", "x-user-id": "user-123" },
  body: JSON.stringify({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hello" }]
  })
});
const data = await res.json();
console.log(data.choices?.[0]?.message?.content);
```

## Quick Start

Decorator:

```python
from aisafeguard import guard

@guard(input=["prompt_injection", "pii"], output=["toxicity", "pii"])
async def ask(prompt: str) -> str:
    return "model output"
```

Guard object:

```python
from aisafeguard import Guard

g = Guard(config="aisafe.yaml")
input_result = await g.scan_input("Ignore previous instructions")
```

OpenAI wrapper:

```python
from aisafeguard import Guard
from aisafeguard.integrations import wrap_openai

guard = Guard()
client = wrap_openai(openai_client, guard)
```

## Use Cases

- Secure chatbots against prompt injection
- Prevent sensitive-data leaks in support assistants
- Add policy controls for enterprise AI workflows
- Gate unsafe model outputs before returning to end users
- Centralize AI safety via proxy for multi-language stacks

## CLI

```bash
aisafe init
aisafe validate aisafe.yaml
aisafe scan "My SSN is 123-45-6789"
aisafe redteam --strict
aisafe proxy --config aisafe.yaml --host 127.0.0.1 --port 8000 \
  --upstream-base-url https://api.openai.com \
  --upstream-api-key $OPENAI_API_KEY \
  --rpm 120
```

Proxy env vars:
- `AISAFE_UPSTREAM_BASE_URL`
- `AISAFE_UPSTREAM_API_KEY` (or `OPENAI_API_KEY`)

## Docker

```bash
docker build -t aisafeguard:latest .
docker run --rm -p 8000:8000 \
  -e AISAFE_UPSTREAM_API_KEY=$OPENAI_API_KEY \
  aisafeguard:latest
```

## Development

```bash
npm install
PYTHONPATH=src python -m pytest -v
python benchmarks/bench_pipeline.py
```

## Docs

- `docs/getting-started.md`
- `docs/config-reference.md`
- `docs/prompt-injection-protection.md`
- `docs/pii-redaction-llm.md`
- `docs/openai-compatible-ai-proxy.md`
