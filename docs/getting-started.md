# Getting Started

1. Create config:

```bash
aisafe init
```

2. Validate config:

```bash
aisafe validate aisafe.yaml
```

3. Use in app:

```python
from aisafeguard import Guard

guard = Guard(config="aisafe.yaml")
result = await guard.scan_input("hello")
print(result.passed)
```

## Next steps

- Prompt injection guide: `docs/prompt-injection-protection.md`
- PII redaction guide: `docs/pii-redaction-llm.md`
- Proxy guide: `docs/openai-compatible-ai-proxy.md`
