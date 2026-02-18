"""Decorator API for AISafe Guard."""

from __future__ import annotations

import functools
from typing import Any, Callable

from aisafeguard.config import GuardConfig, get_default_config, load_config
from aisafeguard.guard import Guard
from aisafeguard.policy import PolicyViolation


def guard(
    input: list[str] | None = None,
    output: list[str] | None = None,
    config: str | None = None,
    on_block: Callable[..., Any] | None = None,
) -> Callable[..., Any]:
    """Decorator that wraps an async function with safety scanning."""
    guard_config = load_config(config) if config else get_default_config()
    selected_config = _select_scanners(guard_config, input, output)
    _guard_instance = Guard(config=selected_config)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            prompt_text, prompt_location = _extract_prompt(args, kwargs)
            call_args = args
            call_kwargs = kwargs.copy()

            if input and prompt_text is not None:
                input_result = await _guard_instance.scan_input(prompt_text)
                if not input_result.passed:
                    try:
                        sanitized = _guard_instance.policy.enforce(input_result)
                    except PolicyViolation:
                        if on_block:
                            return on_block(input_result)
                        raise PolicyViolation(
                            input_result,
                            f"Input blocked by: {', '.join(input_result.failed_scanners)}",
                        )
                    if sanitized:
                        call_args, call_kwargs = _replace_prompt(
                            call_args,
                            call_kwargs,
                            prompt_location,
                            sanitized,
                        )
                        prompt_text = sanitized

            result = await func(*call_args, **call_kwargs)

            if output and isinstance(result, str):
                output_result = await _guard_instance.scan_output(
                    result,
                    context={"input_text": prompt_text} if prompt_text else None,
                )
                if not output_result.passed:
                    try:
                        sanitized = _guard_instance.policy.enforce(output_result)
                    except PolicyViolation:
                        if on_block:
                            return on_block(output_result)
                        raise PolicyViolation(
                            output_result,
                            f"Output blocked by: {', '.join(output_result.failed_scanners)}",
                        )
                    if sanitized:
                        return sanitized

            return result

        return wrapper

    return decorator


def _extract_prompt(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> tuple[str | None, tuple[str, str | int] | None]:
    """Try to extract the prompt string from function arguments."""
    for name in ("prompt", "text", "message", "query", "input"):
        if name in kwargs and isinstance(kwargs[name], str):
            return kwargs[name], ("kwarg", name)

    for i, arg in enumerate(args):
        if isinstance(arg, str):
            return arg, ("arg", i)

    return None, None


def _replace_prompt(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    location: tuple[str, str | int] | None,
    sanitized: str,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    if location is None:
        return args, kwargs

    kind, key = location
    if kind == "kwarg":
        kwargs[str(key)] = sanitized
        return args, kwargs

    mutable_args = list(args)
    mutable_args[int(key)] = sanitized
    return tuple(mutable_args), kwargs


def _select_scanners(
    config: GuardConfig,
    input_scanners: list[str] | None,
    output_scanners: list[str] | None,
) -> GuardConfig:
    resolved = config.model_copy(deep=True)
    if input_scanners is not None:
        resolved.input = {
            name: scanner_config
            for name, scanner_config in resolved.input.items()
            if name in input_scanners
        }
    if output_scanners is not None:
        resolved.output = {
            name: scanner_config
            for name, scanner_config in resolved.output.items()
            if name in output_scanners
        }
    return resolved
