from __future__ import annotations

import httpx

from aisafeguard.proxy.server import create_app


async def _fake_upstream(payload, headers, base_url):
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "email: bob@example.com"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
    }


async def test_proxy_forwards_and_redacts() -> None:
    app = create_app(upstream_api_key="test-key", upstream_handler=_fake_upstream)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"x-user-id": "u1"},
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert "[EMAIL_REDACTED]" in data["choices"][0]["message"]["content"]
    assert data["aisafe"]["user_id"] == "u1"
