# HARP-SESSION Test Vectors (v0.2 Draft)

## Canonicalization Profile

Canonical JSON bytes are produced by:
- UTF-8 encoding
- Object keys sorted lexicographically
- No insignificant whitespace
- No trailing newline

## Test Vector 1: snapshotHash

### SnapshotSignable (WITHOUT `snapshotHash`)

```json
{
  "sessionId": "01J2V8V3M2YF0KX9Q0Z7E6H9R1",
  "eventType": "session.snapshot",
  "snapshotId": "snap-001",
  "snapshotType": "summary",
  "createdAt": "2026-02-21T12:02:00Z",
  "payload": {
    "summary": "Parser refactor planned. Medium risk due to grammar changes.",
    "filesAffected": [
      "parser.py",
      "lexer.py"
    ]
  },
  "snapshotHashAlg": "SHA-256"
}
```

### Canonical bytes (UTF-8)

```text
{"createdAt":"2026-02-21T12:02:00Z","eventType":"session.snapshot","payload":{"filesAffected":["parser.py","lexer.py"],"summary":"Parser refactor planned. Medium risk due to grammar changes."},"sessionId":"01J2V8V3M2YF0KX9Q0Z7E6H9R1","snapshotHashAlg":"SHA-256","snapshotId":"snap-001","snapshotType":"summary"}
```

### SHA-256 (hex)

```text
5145a558f7390a66768c6da0195f12484bb1f01c44b8bc33518733970ac06e5d
```

## Notes

- snapshotHash is computed over canonical JSON of snapshot object excluding `snapshotHash`.
- If metadata is present, it MUST be included in hash input.
