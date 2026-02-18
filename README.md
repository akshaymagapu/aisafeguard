# AISafe Guard

Safety rails for every AI app. `aisafeguard` is a model-agnostic Python toolkit that scans LLM input/output for prompt injection, jailbreaks, PII, toxicity, malicious URLs, and relevance issues.

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

## Release and Publishing

- Python package publish is automated by `/Users/akshay/workspace/safety/aisafeguard/.github/workflows/release.yml`.
- Trigger: push a tag like `v0.1.0`.
- Requirement: set `PYPI_API_TOKEN` in repo secrets.
- npm is currently used only for repo tooling (`commitlint`) via `package.json` and is marked `private`, so it is **not** published to npm.
