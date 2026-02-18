"""LLM provider integrations for AISafe Guard."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any

from aisafeguard.guard import Guard
from aisafeguard.policy import PolicyViolation


@dataclass
class _OpenAICompletionsProxy:
    create_fn: Any
    guard: Guard

    async def create(self, *args: Any, **kwargs: Any) -> Any:
        prompt = _extract_openai_prompt(kwargs)
        if prompt:
            input_result = await self.guard.scan_input(prompt)
            if not input_result.passed:
                self.guard.policy.enforce(input_result)

        response = self.create_fn(*args, **kwargs)
        if inspect.isawaitable(response):
            response = await response

        response_text = _extract_openai_response_text(response)
        if response_text:
            output_result = await self.guard.scan_output(
                response_text,
                context={"input_text": prompt} if prompt else None,
            )
            if not output_result.passed:
                sanitized = self.guard.policy.enforce(output_result)
                if sanitized:
                    _set_openai_response_text(response, sanitized)

        return response


@dataclass
class _OpenAIChatProxy:
    chat: Any
    guard: Guard

    @property
    def completions(self) -> _OpenAICompletionsProxy:
        return _OpenAICompletionsProxy(self.chat.completions.create, self.guard)


@dataclass
class _OpenAIClientProxy:
    client: Any
    guard: Guard

    @property
    def chat(self) -> _OpenAIChatProxy:
        return _OpenAIChatProxy(self.client.chat, self.guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.client, name)


@dataclass
class _AnthropicMessagesProxy:
    create_fn: Any
    guard: Guard

    async def create(self, *args: Any, **kwargs: Any) -> Any:
        prompt = _extract_anthropic_prompt(kwargs)
        if prompt:
            input_result = await self.guard.scan_input(prompt)
            if not input_result.passed:
                self.guard.policy.enforce(input_result)

        response = self.create_fn(*args, **kwargs)
        if inspect.isawaitable(response):
            response = await response

        response_text = _extract_anthropic_response_text(response)
        if response_text:
            output_result = await self.guard.scan_output(
                response_text,
                context={"input_text": prompt} if prompt else None,
            )
            if not output_result.passed:
                sanitized = self.guard.policy.enforce(output_result)
                if sanitized:
                    _set_anthropic_response_text(response, sanitized)

        return response


@dataclass
class _AnthropicClientProxy:
    client: Any
    guard: Guard

    @property
    def messages(self) -> _AnthropicMessagesProxy:
        return _AnthropicMessagesProxy(self.client.messages.create, self.guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.client, name)


def wrap_openai(client: Any, guard: Guard) -> Any:
    """Wrap an OpenAI-compatible client with AISafe Guard scanning."""
    return _OpenAIClientProxy(client=client, guard=guard)


def wrap_anthropic(client: Any, guard: Guard) -> Any:
    """Wrap an Anthropic-compatible client with AISafe Guard scanning."""
    return _AnthropicClientProxy(client=client, guard=guard)


def _extract_openai_prompt(kwargs: dict[str, Any]) -> str:
    messages = kwargs.get("messages", [])
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        if message.get("role") == "user" and isinstance(message.get("content"), str):
            return message["content"]
    return ""


def _extract_openai_response_text(response: Any) -> str:
    choices = getattr(response, "choices", None)
    if not choices:
        return ""
    first = choices[0]
    message = getattr(first, "message", None)
    content = getattr(message, "content", None)
    return content if isinstance(content, str) else ""


def _set_openai_response_text(response: Any, sanitized: str) -> None:
    choices = getattr(response, "choices", None)
    if not choices:
        return
    first = choices[0]
    message = getattr(first, "message", None)
    if message is not None and hasattr(message, "content"):
        message.content = sanitized


def _extract_anthropic_prompt(kwargs: dict[str, Any]) -> str:
    messages = kwargs.get("messages", [])
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            text_parts: list[str] = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str):
                        text_parts.append(text)
            return " ".join(text_parts)
    return ""


def _extract_anthropic_response_text(response: Any) -> str:
    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return ""
    text_blocks: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            text_blocks.append(text)
    return " ".join(text_blocks)


def _set_anthropic_response_text(response: Any, sanitized: str) -> None:
    content = getattr(response, "content", None)
    if not isinstance(content, list) or not content:
        return
    first = content[0]
    if hasattr(first, "text"):
        first.text = sanitized


__all__ = ["wrap_openai", "wrap_anthropic"]
