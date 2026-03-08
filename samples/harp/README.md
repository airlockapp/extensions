# HARP Samples — Multi-Language Reference Implementations

> **HARP — Human Authorization & Review Protocol**
> Version 0.2 Draft

Working reference implementations of the [HARP-CORE specification](https://github.com/harp-protocol/harp-spec) — a cryptographically verifiable human authorization layer for autonomous AI agent actions.


[HARP Docs](https://harp-protocol.github.io/)

---

## What Is HARP?

HARP ensures that every sensitive AI agent action is **explicitly bound to human approval** through cryptographic signatures. It prevents substitution, replay, relay forgery, and enforcement bypass attacks by design.

```
 ┌───────────┐       ┌──────────────────┐       ┌────────────┐
 │  AI Agent │──────▶│  HARP Enforcer   │──────▶│  Execution │
 │ (proposes)│       │ (intercepts      │       │  (gated)   │
 └───────────┘       │  & gates)        │       └────────────┘
                     └────────┬─────────┘
                              │ artifact-wire.json
                              ▼
                     ┌──────────────────┐
                     │ Mobile Approver  │
                     │ (reviews & signs)│
                     └────────┬─────────┘
                              │ decision.json
                              ▼
                     ┌──────────────────┐
                     │  HARP Enforcer   │
                     │ (verifies &      │
                     │  enforces)       │
                     └──────────────────┘
```

---

## Implementations

| Language       | Directory                                     | Crypto Stack                              | Runner       |
| -------------- | --------------------------------------------- | ----------------------------------------- | ------------ |
| **C#**         | [`src/csharp/`](src/csharp/README.md)         | `NSec` (libsodium)                        | `dotnet run` |
| **Node.js**    | [`src/node/`](src/node/README.md)             | `libsodium-wrappers-sumo` + `node:crypto` | `node`       |
| **Python**     | [`src/python/`](src/python/README.md)         | `PyNaCl` + `hashlib`                      | `python`     |
| **TypeScript** | [`src/typescript/`](src/typescript/README.md) | `libsodium-wrappers-sumo` + `node:crypto` | `tsx`        |
| **Go**         | [`src/go/`](src/go/README.md)                 | `x/crypto` + `crypto/ed25519` (stdlib)    | `go run`     |
| **Rust**       | [`src/rust/`](src/rust/README.md)             | RustCrypto (pure Rust, no C deps)         | `cargo run`  |

All six implementations are **wire-compatible** — artifacts encrypted by any implementation can be decrypted by the others, and decisions signed by any can be verified by the others, provided the same key material is used.

---

## Repository Structure

```
harp-samples/
├── README.md                   ← You are here
└── src/
    ├── spec/                   HARP protocol specification suite
    │   ├── core/               HARP-CORE (mandatory)
    │   ├── prompt/             HARP-PROMPT (optional extension)
    │   ├── session/            HARP-SESSION (optional extension)
    │   ├── infrastructure/     Transport, key mgmt, threat model, compliance
    │   └── governance/         Versioning, registries, change control
    ├── csharp/                 C# reference implementation (.NET 8)
    ├── node/                   Node.js reference implementation (ESM)
    ├── python/                 Python reference implementation (3.9+)
    ├── typescript/             TypeScript reference implementation (strict mode)
    ├── go/                     Go reference implementation (1.26+)
    └── rust/                   Rust reference implementation (2021 edition)
```

---

## Quick Start

Each implementation follows the same **4-step demo flow**:

```bash
# Step 1: Generate MA keys (first run only)
<runner> harp-approver

# Step 2: Build & encrypt artifact
<runner> harp-executor

# Step 3: Decrypt, review & sign (type 'y' to approve)
<runner> harp-approver

# Step 4: Verify signature & enforce
<runner> harp-enforcer
```

Replace `<runner>` with the language-specific command:

| Language   | Step 1 & 3                           | Step 2                               | Step 4                               |
| ---------- | ------------------------------------ | ------------------------------------ | ------------------------------------ |
| C#         | `dotnet run --project Harp.Approver` | `dotnet run --project Harp.Executor` | `dotnet run --project Harp.Enforcer` |
| Node.js    | `node harp-approver.mjs`             | `node harp-executor.mjs`             | `node harp-enforcer.mjs`             |
| Python     | `python harp_approver.py`            | `python harp_executor.py`            | `python harp_enforcer.py`            |
| TypeScript | `npx tsx src/harp-approver.ts`       | `npx tsx src/harp-executor.ts`       | `npx tsx src/harp-enforcer.ts`       |
| Go         | `go run ./cmd/harp-approver/`        | `go run ./cmd/harp-executor/`        | `go run ./cmd/harp-enforcer/`        |
| Rust       | `cargo run --bin harp-approver`      | `cargo run --bin harp-executor`      | `cargo run --bin harp-enforcer`      |

All implementations write generated files to `C:\tmp\harp\` by default.

---

## Cryptographic Architecture

All implementations share the same cryptographic architecture:

| Function           | Algorithm              | Purpose                                              |
| ------------------ | ---------------------- | ---------------------------------------------------- |
| Key Exchange       | **X25519**             | Derive shared secret between HE and MA               |
| Key Derivation     | **HKDF-SHA256**        | Derive symmetric AEAD key from shared secret         |
| Payload Encryption | **XChaCha20-Poly1305** | AEAD encryption of artifact payload                  |
| Artifact Hashing   | **SHA-256**            | Deterministic hash of canonicalized artifact         |
| Decision Signing   | **Ed25519**            | Human-bound cryptographic approval signature         |
| Canonicalization   | **RFC 8785 (JCS)**     | Deterministic JSON for cross-platform hash agreement |

---

## Wire Format

### artifact-wire.json

```json
{
  "requestId": "...",
  "artifactType": "command.review",
  "repoRef": "repo:opaque:demo",
  "createdAt": "2026-02-24T...",
  "expiresAt": "2026-02-24T...",
  "artifactHashAlg": "SHA-256",
  "artifactHash": "<64-hex>",
  "enc": {
    "kdf": "X25519+HKDF-SHA256",
    "encAlg": "XChaCha20-Poly1305",
    "maKxPub": "<base64url>",
    "heKxPub": "<base64url>",
    "salt": "<base64url>",
    "info": "HARP-XCHACHA-PAYLOAD-V1",
    "nonce": "<base64url>",
    "ciphertext": "<base64url>",
    "tag": "<base64url>"
  }
}
```

### decision.json

```json
{
  "requestId": "...",
  "artifactHashAlg": "SHA-256",
  "artifactHash": "<64-hex>",
  "repoRef": "repo:opaque:demo",
  "decision": "allow",
  "scope": "once",
  "expiresAt": "2026-02-24T...",
  "nonce": "<base64url>",
  "sigAlg": "Ed25519",
  "signerKeyId": "ma-key-1",
  "signature": "<base64url>"
}
```

---

## Security Guarantees

| Guarantee                        | Mechanism                                        |
| -------------------------------- | ------------------------------------------------ |
| ✔ Confidential payload           | XChaCha20-Poly1305 AEAD with X25519 key exchange |
| ✔ Integrity                      | AEAD authentication + AAD binding                |
| ✔ Cryptographic approval binding | Ed25519 signature over `artifactHash`            |
| ✔ Signature authenticity         | Ed25519 verification with known `signerKeyId`    |
| ✔ Replay resistance              | Nonce journal + expiration enforcement           |
| ✔ Deterministic canonicalization | RFC 8785 JCS for cross-platform hash agreement   |

---

## Testing Failure Scenarios

Each implementation's README documents 7 testable rejection scenarios:

1. **Replay detection** — Run enforcer twice; nonce journal blocks reuse
2. **Deny decision** — Type `n` at approval prompt; enforcer exits with code 2
3. **Tampered artifact** — Edit `repoRef` in `artifact-wire.json`; hash mismatch
4. **Tampered decision** — Edit `decision` field without re-signing; signature fails
5. **Expired artifact/decision** — Wait beyond TTL; expiry check rejects
6. **Wrong key** — Regenerate keys; old decision signature fails
7. **Binding mismatch** — Edit `requestId` in `decision.json`; binding check fails

---

## Production Considerations

These are **demo implementations**. For production deployment, consider:

- **Secure key storage** — OS keychain, HSM, or secret manager
- **mTLS transport binding** — TLS with mutual certificate authentication
- **Structured logging** — Audit trail for all enforcement decisions
- **Multi-approver quorum** — Require multiple human approvals
- **Key rotation** — Automated key lifecycle management
- **Clock skew handling** — Configurable tolerance (RECOMMENDED: 60 seconds)
- **Rate limiting** — Protect MA from DoS
- **Revocation enforcement** — CRL or OCSP-like mechanism for compromised keys

---

## Specification

The full HARP specification suite is available in [`src/spec/`](src/spec/README.md), covering:

- **HARP-CORE** — Mandatory cryptographic authorization foundation
- **HARP-PROMPT** — Optional prompt control extension
- **HARP-SESSION** — Optional session lifecycle extension
- **HARP-TRANSPORT** — HTTP & WebSocket bindings
- **HARP-KEYMGMT** — Key lifecycle management
- **HARP-THREATMODEL** — Formal security analysis
- **HARP-COMPLIANCE** — Conformance & interoperability testing
- **HARP-GOVERNANCE** — Protocol evolution & registry control

---

## License

Specification text may be released under an open documentation license (e.g., CC BY 4.0).
Reference implementations may use appropriate open-source licenses.
