# OpenAI-Compatible AI Safety Proxy

`aisafeguard` includes a FastAPI proxy that exposes an OpenAI-compatible `chat/completions` endpoint.

## Why use proxy mode

- Add guardrails without changing every application code path
- Enforce shared safety policy across teams/languages
- Apply rate limiting and usage tracking in one place

## Run the proxy

```bash
aisafe proxy --config aisafe.yaml --host 127.0.0.1 --port 8000 \
  --upstream-base-url https://api.openai.com \
  --upstream-api-key $OPENAI_API_KEY
```

## Endpoint

- `POST /v1/chat/completions`
- `GET /health`
- `GET /v1/usage/{user_id}`

## Node example

```js
const res = await fetch("http://localhost:8000/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json", "x-user-id": "user-123" },
  body: JSON.stringify({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: "Hello" }]
  })
});
```

## Related docs

- `docs/getting-started.md`
- `docs/config-reference.md`
