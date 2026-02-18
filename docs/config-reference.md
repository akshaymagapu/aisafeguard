# Config Reference

`aisafe.yaml`:

```yaml
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
output:
  pii:
    enabled: true
    entities: [EMAIL, PHONE, SSN, CREDIT_CARD]
    action: redact
```

Scanner options:
- `enabled`: boolean
- `threshold`: float (0-1)
- `action`: `block | warn | log | redact`
- `entities`: PII entity list
- `banned_topics`: topic-ban list
