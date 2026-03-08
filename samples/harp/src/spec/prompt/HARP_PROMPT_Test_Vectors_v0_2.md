# HARP-PROMPT Test Vectors (v0.2 Draft)

This document provides deterministic canonicalization and hashing test vectors for the HARP-PROMPT extension.

## Canonicalization Profile

Canonical JSON bytes are produced by:
- UTF-8 encoding
- Object keys sorted lexicographically
- No insignificant whitespace (separators `,` and `:`)
- No trailing newline

Implementations MUST reproduce the exact byte sequence below.

## Test Vector 1: promptHash

### PromptSignable (WITHOUT `promptHash`)

```json
{
  "requestId": "01J2V9K3M2W1J5R6S7T8U9V0W1",
  "sessionId": "01J2V8V3M2YF0KX9Q0Z7E6H9R1",
  "repoRef": "repo:acme/widgets",
  "artifactType": "prompt.send",
  "createdAt": "2026-02-21T12:01:00Z",
  "target": "agentChat",
  "text": "Please summarize the plan and list risks. Keep it concise.",
  "promptHashAlg": "SHA-256"
}
```

### Canonical bytes (UTF-8)

```text
{"artifactType":"prompt.send","createdAt":"2026-02-21T12:01:00Z","promptHashAlg":"SHA-256","repoRef":"repo:acme/widgets","requestId":"01J2V9K3M2W1J5R6S7T8U9V0W1","sessionId":"01J2V8V3M2YF0KX9Q0Z7E6H9R1","target":"agentChat","text":"Please summarize the plan and list risks. Keep it concise."}
```

### SHA-256 (hex)

```text
0b18f65f2e4d81b0bbfa89267138163a439ee2381393f95b41f01fbdfdbabd50
```

## Notes

- `promptHash` is computed over the canonical JSON of the prompt object excluding `promptHash`.
- If optional fields (e.g., `metadata`, `extensions`) are present, they MUST be included in the hash input.
