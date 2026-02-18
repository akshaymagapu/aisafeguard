"""OpenAI-compatible proxy server."""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from typing import Any

from aisafeguard.guard import Guard
from aisafeguard.policy import PolicyViolation
from starlette.requests import Request


class RateLimiter:
    """In-memory sliding-window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        queue = self._hits[key]
        while queue and now - queue[0] > self.window_seconds:
            queue.popleft()
        if len(queue) >= self.max_requests:
            return False
        queue.append(now)
        return True


class CostTracker:
    """Simple per-user cost tracker from usage tokens."""

    def __init__(self, default_price_per_1k_tokens: float = 0.002) -> None:
        self.default_price_per_1k_tokens = default_price_per_1k_tokens
        self._spent_usd: dict[str, float] = defaultdict(float)

    def add_usage(self, user_id: str, usage: dict[str, Any] | None) -> float:
        if not usage:
            return self._spent_usd[user_id]
        total_tokens = usage.get("total_tokens", 0)
        if not isinstance(total_tokens, int):
            return self._spent_usd[user_id]
        delta = (total_tokens / 1000.0) * self.default_price_per_1k_tokens
        self._spent_usd[user_id] += delta
        return self._spent_usd[user_id]

    def get_spend(self, user_id: str) -> float:
        return self._spent_usd[user_id]


def create_app(
    config: str | None = None,
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    max_requests_per_minute: int = 60,
    upstream_handler: Any | None = None,
) -> Any:
    from fastapi import FastAPI, HTTPException
    import httpx

    app = FastAPI(title="AISafe Proxy", version="0.1.0")
    guard = Guard(config=config) if config else Guard()
    limiter = RateLimiter(max_requests=max_requests_per_minute, window_seconds=60)
    costs = CostTracker()

    base_url = upstream_base_url or os.getenv("AISAFE_UPSTREAM_BASE_URL", "https://api.openai.com")
    api_key = upstream_api_key or os.getenv("AISAFE_UPSTREAM_API_KEY", os.getenv("OPENAI_API_KEY", ""))

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/usage/{user_id}")
    async def usage(user_id: str) -> dict[str, Any]:
        return {"user_id": user_id, "spent_usd": round(costs.get_spend(user_id), 6)}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Any:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail={"error": "invalid_payload"})

        user_id = (
            request.headers.get("x-user-id")
            or str(payload.get("user"))
            or "anonymous"
        )
        if not limiter.allow(user_id):
            raise HTTPException(status_code=429, detail={"error": "rate_limit_exceeded"})

        messages = payload.get("messages", [])
        user_prompt = _extract_user_prompt(messages)

        if user_prompt:
            input_result = await guard.scan_input(user_prompt)
            if not input_result.passed:
                try:
                    sanitized_input = guard.policy.enforce(input_result)
                except PolicyViolation:
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "blocked_input",
                            "failed_scanners": input_result.failed_scanners,
                            "findings": [f.model_dump() for f in input_result.findings],
                        },
                    ) from None
                if sanitized_input:
                    _replace_user_prompt(messages, sanitized_input)
                    payload["messages"] = messages
                    user_prompt = sanitized_input

        upstream_headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if not api_key:
            raise HTTPException(
                status_code=500,
                detail={"error": "missing_upstream_api_key"},
            )

        if upstream_handler is not None:
            upstream_json = await upstream_handler(payload, upstream_headers, base_url)
        else:
            async with httpx.AsyncClient(timeout=60.0) as client:
                upstream_response = await client.post(
                    f"{base_url.rstrip('/')}/v1/chat/completions",
                    headers=upstream_headers,
                    json=payload,
                )

            if upstream_response.status_code >= 400:
                raise HTTPException(status_code=upstream_response.status_code, detail=upstream_response.text)

            upstream_json = upstream_response.json()
        output_text = _extract_assistant_text(upstream_json)

        if output_text:
            output_result = await guard.scan_output(output_text, context={"input_text": user_prompt})
            if not output_result.passed:
                try:
                    sanitized_output = guard.policy.enforce(output_result)
                except PolicyViolation:
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "blocked_output",
                            "failed_scanners": output_result.failed_scanners,
                            "findings": [f.model_dump() for f in output_result.findings],
                        },
                    ) from None
                if sanitized_output:
                    _replace_assistant_text(upstream_json, sanitized_output)

        total_spend = costs.add_usage(user_id, upstream_json.get("usage"))
        upstream_json.setdefault("aisafe", {})
        upstream_json["aisafe"]["user_id"] = user_id
        upstream_json["aisafe"]["spent_usd"] = round(total_spend, 6)

        return upstream_json

    return app


def _extract_user_prompt(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                return content
    return ""


def _replace_user_prompt(messages: Any, value: str) -> None:
    if not isinstance(messages, list):
        return
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            message["content"] = value
            return


def _extract_assistant_text(response_json: dict[str, Any]) -> str:
    choices = response_json.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _replace_assistant_text(response_json: dict[str, Any], value: str) -> None:
    choices = response_json.get("choices")
    if not isinstance(choices, list) or not choices:
        return
    first = choices[0]
    if not isinstance(first, dict):
        return
    message = first.get("message")
    if not isinstance(message, dict):
        return
    message["content"] = value
