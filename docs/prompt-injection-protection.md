# Prompt Injection Protection for LLM Apps

`aisafeguard` provides prompt injection protection by scanning user input before it reaches your model.

## What it detects

- Instruction override attempts
- System prompt extraction attempts
- Role/persona manipulation
- Delimiter/token smuggling patterns
- Common jailbreak crossover prompts

## Quick example

```python
from aisafeguard import guard

@guard(input=["prompt_injection"], output=[])
async def ask(prompt: str) -> str:
    return await llm_call(prompt)
```

## Policy behavior

- `block`: stop request and raise policy violation
- `warn`: allow request but flag findings
- `log`: allow request and log findings
- `redact`: return sanitized text when scanner supports it

## Related docs

- `docs/getting-started.md`
- `docs/config-reference.md`
