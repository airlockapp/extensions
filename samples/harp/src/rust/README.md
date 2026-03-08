# HARP Rust Reference Implementation

> **HARP — Human Authorization & Review Protocol**
> Version 0.2 Draft · Rust 2021 Edition · RustCrypto

A working reference implementation of the **HARP-CORE** specification — a cryptographically verifiable human authorization layer for autonomous AI agent actions.

---

## What Is HARP?

HARP ensures that every sensitive AI agent action is **explicitly bound to human approval** through cryptographic signatures. It prevents substitution, replay, relay forgery, and enforcement bypass attacks by design.

```
┌─────────────┐        ┌───────────────────────┐        ┌──────────────┐
│  AI Agent   │───────▶│  HARP Enforcer (HE)   │───────▶│   Execution  │
│  (proposes) │        │  (intercepts & gates)  │        │   (allowed   │
└─────────────┘        └──────────┬─────────────┘        │    only if   │
                                  │                      │   approved)  │
                                  │  artifact-wire.json  └──────────────┘
                                  ▼
                       ┌───────────────────────┐
                       │  Mobile Approver (MA)  │
                       │  (reviews & signs)     │
                       └───────────────────────┘
                                  │
                                  │  decision.json
                                  ▼
                       ┌───────────────────────┐
                       │  HARP Enforcer (HE)   │
                       │  (verifies & enforces) │
                       └───────────────────────┘
```

### Actors

| Actor | Role | This Implementation |
|-------|------|---------------------|
| **AI Agent** | Produces candidate actions (plans, patches, commands) | *(implicit — payload is hardcoded in demo)* |
| **HARP Enforcer (HE)** | Intercepts actions, builds encrypted artifacts, verifies decisions, gates execution | `harp-executor` (proposer) + `harp-enforcer` (verifier) |
| **Mobile Approver (MA)** | Human-controlled device that reviews artifact content and signs decisions | `harp-approver` |
| **Gateway (GW)** | Optional untrusted relay (not implemented in this demo) | — |

---

## Project Structure

```
src/rust/
├── Cargo.toml
└── src/
    ├── lib.rs                          Module root
    ├── models.rs                       Structs for ArtifactWire, Decision, EncBlob, MaKeys
    ├── crypto_helpers.rs               Base64url, SHA-256, HKDF, X25519, XChaCha20, Ed25519
    ├── canonical_json.rs               JCS canonicalization (RFC 8785)
    ├── nonce_journal.rs                Append-only nonce replay journal
    └── bin/
        ├── harp_executor.rs            HE Proposer — builds & encrypts artifacts
        ├── harp_approver.rs            Mobile Approver — generates keys, decrypts, signs
        └── harp_enforcer.rs            HE Verifier — verifies signatures & enforces
```

---

## Rust-Specific Design

This implementation follows idiomatic Rust patterns:

| Pattern | Usage |
|---------|-------|
| `#[derive(Serialize, Deserialize)]` | Zero-boilerplate JSON with `serde` |
| `#[serde(rename_all = "camelCase")]` | Wire-compatible JSON keys without manual mapping |
| `#[serde(skip_serializing_if)]` | Null-equivalent omission for `Option<T>` fields |
| `!` (never type) | `fail()` returns `!` for exhaustive error handling |
| `Result<T, E>` | All fallible operations use `Result` |
| `match` expressions | Decision and scope enforcement via pattern matching |
| RustCrypto ecosystem | Pure-Rust crypto with no C/OpenSSL dependencies |
| `src/bin/` layout | Multiple binaries in a single Cargo project |

---

## Cryptographic Architecture

This implementation uses the **RustCrypto** ecosystem — pure-Rust implementations with no C bindings or OpenSSL dependency.

### Key Exchange

| Property | Value |
|----------|-------|
| Algorithm | **X25519** |
| Purpose | Derive shared secret between HE and MA |
| Crate | `x25519-dalek` |

### Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | **HKDF-SHA256** |
| Salt | 16 random bytes (per-artifact) |
| Info | `HARP-XCHACHA-PAYLOAD-V1` |
| Output | 32-byte symmetric key for AEAD |
| Crate | `hkdf` + `sha2` |

### Payload Encryption

| Property | Value |
|----------|-------|
| Algorithm | **XChaCha20-Poly1305** (AEAD) |
| Nonce size | 24 bytes |
| Tag size | 16 bytes |
| Mode | Detached (ciphertext + tag stored separately) |
| AAD | Canonicalized artifact header + `artifactHash` |
| Crate | `chacha20poly1305` |

### Artifact Hashing

| Property | Value |
|----------|-------|
| Algorithm | **SHA-256** |
| Input | JCS-canonicalized artifact **without** `artifactHash` field |
| Output | 64 lowercase hex characters |
| Crate | `sha2` |

### Decision Signing

| Property | Value |
|----------|-------|
| Algorithm | **Ed25519** |
| Signed object | `DecisionSignable` (canonical JSON bytes) |
| Output | 64-byte raw signature, base64url encoded |
| Crate | `ed25519-dalek` |

---

## Running the Demo

### Prerequisites

- Rust 1.60+ (2021 edition)

### Build

```bash
cd src/rust
cargo build
```

### Run the 4-Step Flow

All generated files are written to `C:\tmp\harp\` by default.

```bash
# Step 1: Generate MA keys
cargo run --bin harp-approver

# Step 2: Build encrypted artifact
cargo run --bin harp-executor

# Step 3: Decrypt & approve (type 'y' to allow, 'n' to deny)
cargo run --bin harp-approver

# Step 4: Verify signature & enforce
cargo run --bin harp-enforcer
```

### Expected Output

```
# Step 1
Generating MA keys...
✅ Wrote C:\tmp\harp\ma-keys.json

# Step 2
Loaded MA public keys:
  MA X25519 pub: ...
  MA Ed25519 pub: ...
  signerKeyId: ma-key-1
✅ Wrote artifact-wire.json
artifactHash: <64-hex-characters>

# Step 3
✅ Payload decrypted and artifactHash verified.
----- REVIEW PAYLOAD -----
{"command":"echo \"hello harp\"","timeoutSeconds":10,"workingDirectory":"/tmp"}
--------------------------
Approve? (y/n): y
✅ Wrote C:\tmp\harp\decision.json (allow)

# Step 4
✅ Decision verified and bound to artifactHash.
Decision: allow  Scope: once
ArtifactType: command.review
RepoRef: repo:opaque:demo
ArtifactHash: <64-hex-characters>
🟢 ENFORCER RESULT: ALLOW
```

### Clean Up & Rerun

```bash
rm C:\tmp\harp\ma-keys.json
rm C:\tmp\harp\artifact-wire.json
rm C:\tmp\harp\decision.json
rm C:\tmp\harp\nonce-journal.ndjson
```

---

## Testing Failure Scenarios

After completing a successful 4-step flow, you can test the following rejection scenarios:

### 1. Replay Detection

Run the enforcer a second time without re-approving.

```bash
cargo run --bin harp-enforcer
# ❌ REJECT: Replay detected (nonce already seen)
```

### 2. Deny Decision

When prompted in Step 3, type `n` to deny the request.

```bash
cargo run --bin harp-approver
# Approve? (y/n): n

cargo run --bin harp-enforcer
# 🔴 ENFORCER RESULT: DENY (exit code 2)
```

### 3. Tampered Artifact (Hash Mismatch)

After Step 2, manually edit `artifact-wire.json` — change any header field.

```bash
cargo run --bin harp-executor
# Edit C:\tmp\harp\artifact-wire.json → change "repoRef"

cargo run --bin harp-approver
# ❌ Hash mismatch. Refuse.
```

### 4. Tampered Decision (Signature Fails)

After Step 3, edit `decision.json` — change `decision` from `"allow"` to `"deny"` without re-signing.

```bash
cargo run --bin harp-enforcer
# ❌ REJECT: Invalid signature
```

### 5. Expired Artifact or Decision

Wait longer than the TTL (5 minutes for artifact, 10 minutes for decision).

```bash
cargo run --bin harp-enforcer
# ❌ REJECT: Artifact expired at ...
```

### 6. Wrong Key (Key Mismatch)

Delete `ma-keys.json` to regenerate keys, then try to enforce the old decision.

```bash
rm C:\tmp\harp\ma-keys.json
cargo run --bin harp-approver

cargo run --bin harp-enforcer
# ❌ REJECT: Invalid signature
```

### 7. Binding Mismatch

Edit `decision.json` and change `requestId`.

```bash
cargo run --bin harp-enforcer
# ❌ REJECT: Decision.requestId != Artifact.requestId
```

---

## Files Generated

| File | Generated By | Contents |
|------|-------------|----------|
| `ma-keys.json` | harp-approver (Step 1) | X25519 + Ed25519 keypairs, signerKeyId |
| `artifact-wire.json` | harp-executor (Step 2) | Artifact with encrypted payload + enc blob |
| `decision.json` | harp-approver (Step 3) | Signed allow/deny decision token |
| `nonce-journal.ndjson` | harp-enforcer (Step 4) | Append-only replay protection journal |

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_json` | JSON serialization with derive macros |
| `x25519-dalek` | X25519 key exchange |
| `ed25519-dalek` | Ed25519 signing and verification |
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD |
| `hkdf` + `sha2` | HKDF-SHA256 key derivation |
| `base64` | Base64url encoding/decoding |
| `rand` | Cryptographically secure randomness |
| `chrono` | ISO 8601 timestamp formatting and parsing |

All cryptographic crates are from the [RustCrypto](https://github.com/RustCrypto) project — pure Rust with no C/OpenSSL dependencies.

---

## Cross-Language Interoperability

This Rust implementation produces **wire-compatible** output with the [C# reference implementation](../csharp/README.md), the [Node.js reference implementation](../node/README.md), the [Python reference implementation](../python/README.md), the [TypeScript reference implementation](../typescript/README.md), and the [Go reference implementation](../go/README.md).

---

## Security Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| ✔ Confidential payload | XChaCha20-Poly1305 AEAD with X25519 key exchange |
| ✔ Integrity | AEAD authentication + AAD binding |
| ✔ Cryptographic approval binding | Ed25519 signature over `artifactHash` |
| ✔ Signature authenticity | Ed25519 verification with known `signerKeyId` |
| ✔ Replay resistance | Nonce journal + expiration enforcement |
| ✔ Deterministic canonicalization | RFC 8785 JCS for cross-platform hash agreement |
| ✔ Memory safety | Rust's ownership model prevents buffer overflows |

---

## Production Considerations

This is a **demo implementation**. For production deployment, consider:

- **Secure key storage** — OS keychain, environment variables, or secret manager instead of JSON files
- **mTLS transport binding** — TLS with mutual certificate authentication
- **Structured logging** — Audit trail for all enforcement decisions
- **Multi-approver quorum** — Require multiple human approvals for critical actions
- **Key rotation** — Automated key lifecycle management
- **Clock skew handling** — Configurable tolerance (RECOMMENDED: 60 seconds)
- **Rate limiting** — Protect MA from DoS via excessive approval requests
- **Revocation enforcement** — CRL or OCSP-like mechanism for compromised keys
- **Zeroize** — Use the `zeroize` crate to scrub secrets from memory
