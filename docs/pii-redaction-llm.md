# PII Redaction for LLM Input and Output

Use `aisafeguard` to detect and redact personally identifiable information (PII) in prompts and model responses.

## Supported entities (default scanner)

- `EMAIL`
- `PHONE`
- `SSN`
- `CREDIT_CARD`
- `IP_ADDRESS`
- `DATE_OF_BIRTH`

## Example config

```yaml
input:
  pii:
    enabled: true
    entities: [EMAIL, PHONE, SSN, CREDIT_CARD]
    action: redact

output:
  pii:
    enabled: true
    entities: [EMAIL, PHONE, SSN, CREDIT_CARD]
    action: redact
```

## Typical flow

1. Scan input before model call
2. Redact sensitive entities if found
3. Scan output before returning to user
4. Redact leaked sensitive entities

## Related docs

- `docs/config-reference.md`
- `docs/getting-started.md`
