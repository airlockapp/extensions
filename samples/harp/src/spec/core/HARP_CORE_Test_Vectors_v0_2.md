# HARP-CORE Test Vectors (v0.2 Draft)

This document provides deterministic canonicalization, hashing, and signing test vectors for HARP-CORE implementations.

## Canonicalization

Canonical JSON bytes are produced by:
- UTF-8 encoding
- Object keys sorted lexicographically
- No insignificant whitespace (separators `,` and `:`)
- No trailing newline

Implementations MUST reproduce the exact byte sequences shown below.

## Test Vector 1: Artifact Hash

### Artifact (signable form: WITHOUT `artifactHash`)

```json
{
  "requestId": "01J2V8V3K6B2Z9X6G1V7Y2QK8H",
  "sessionId": "01J2V8V3M2YF0KX9Q0Z7E6H9R1",
  "artifactType": "plan.review",
  "repoRef": "repo:acme/widgets",
  "baseRevision": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "createdAt": "2026-02-21T12:00:00Z",
  "expiresAt": "2026-02-21T12:10:00Z",
  "payload": {
    "kind": "plan",
    "title": "Refactor Parser",
    "steps": [
      "Extract tokenizer",
      "Add unit tests",
      "Replace recursive descent with Pratt parser"
    ],
    "risk": "medium"
  },
  "artifactHashAlg": "SHA-256"
}
```

### Canonical bytes (UTF-8)

```text
{"artifactHashAlg":"SHA-256","artifactType":"plan.review","baseRevision":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","createdAt":"2026-02-21T12:00:00Z","expiresAt":"2026-02-21T12:10:00Z","payload":{"kind":"plan","risk":"medium","steps":["Extract tokenizer","Add unit tests","Replace recursive descent with Pratt parser"],"title":"Refactor Parser"},"repoRef":"repo:acme/widgets","requestId":"01J2V8V3K6B2Z9X6G1V7Y2QK8H","sessionId":"01J2V8V3M2YF0KX9Q0Z7E6H9R1"}
```

### SHA-256 (hex)

```text
8e326e1f69e5859a3b5b12965f06b5829f09b12d1748aa2fddb609fb44f831c1
```

## Test Vector 2: Decision Signature (Ed25519)

### Signer public key (raw, base64url)

```text
68GYuLi_rncjJ4w7MWKfKd5ygpeXzMjCzM5tlDakz_I
```

### DecisionSignable canonical JSON

```text
{"artifactHash":"8e326e1f69e5859a3b5b12965f06b5829f09b12d1748aa2fddb609fb44f831c1","artifactHashAlg":"SHA-256","decision":"allow","expiresAt":"2026-02-21T12:05:00Z","nonce":"bm9uY2UtMDAx","repoRef":"repo:acme/widgets","requestId":"01J2V8V3K6B2Z9X6G1V7Y2QK8H","scope":"once","sigAlg":"Ed25519","signerKeyId":"ma-key-01"}
```

### Signature (raw, base64url)

```text
tszU90YldEomMTTrJpUYz-h8xXcAvJ6U97aaEy-1-Oo_vkCx3o63aZps6dN0VaJVKmXY2UnVW6ldoCuXv5sZDA
```

## Notes

- Signature input is the canonical JSON bytes of DecisionSignable (Decision without `signature`).
- Signature is the raw 64-byte Ed25519 signature encoded base64url (no padding).
