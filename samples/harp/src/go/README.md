# HARP Go Reference Implementation

> **HARP — Human Authorization & Review Protocol**
> Version 0.2 Draft · Go 1.26+ · `x/crypto`

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
| **HARP Enforcer (HE)** | Intercepts actions, builds encrypted artifacts, verifies decisions, gates execution | `cmd/harp-executor/` (proposer) + `cmd/harp-enforcer/` (verifier) |
| **Mobile Approver (MA)** | Human-controlled device that reviews artifact content and signs decisions | `cmd/harp-approver/` |
| **Gateway (GW)** | Optional untrusted relay (not implemented in this demo) | — |

---

## Project Structure

```
src/go/
├── go.mod
├── go.sum
├── cmd/
│   ├── harp-executor/
│   │   └── main.go         HE Proposer — builds & encrypts artifacts
│   ├── harp-approver/
│   │   └── main.go         Mobile Approver — generates keys, decrypts, signs
│   └── harp-enforcer/
│       └── main.go         HE Verifier — verifies signatures & enforces
└── internal/
    ├── models/
    │   └── models.go        Structs for ArtifactWire, Decision, EncBlob, MaKeys
    ├── crypto/
    │   └── crypto.go        Base64url, SHA-256, HKDF, X25519, XChaCha20, Ed25519
    ├── canonical/
    │   └── canonical.go     JCS canonicalization (RFC 8785)
    └── journal/
        └── journal.go       Append-only nonce replay journal
```

---

## Go-Specific Design

This implementation follows idiomatic Go patterns:

| Pattern | Usage |
|---------|-------|
| `cmd/` layout | One `main.go` per executable in `cmd/<name>/` |
| `internal/` | Shared packages accessible only within this module |
| Explicit error returns | All fallible operations return `(result, error)` |
| `crypto/ed25519` | Standard library Ed25519 — no external dependency |
| `crypto/rand` | CSPRNG from standard library |
| `encoding/json` | Struct tags with `json:"..."` and `omitempty` |
| Struct embedding | `Decision` embeds `DecisionSignable` for DRY JSON serialization |
| No frameworks | Zero external dependencies beyond `x/crypto` |

---

## Cryptographic Architecture

This implementation uses Go's **standard library** for Ed25519 and SHA-256, and **`golang.org/x/crypto`** for curve25519, HKDF, and XChaCha20-Poly1305. JCS canonicalization is implemented via `encoding/json` (which already sorts map keys).

### Key Exchange

| Property | Value |
|----------|-------|
| Algorithm | **X25519** |
| Purpose | Derive shared secret between HE (Executor) and MA (Approver) |
| Library | `golang.org/x/crypto/curve25519` |

### Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | **HKDF-SHA256** |
| Salt | 16 random bytes (per-artifact) |
| Info | `HARP-XCHACHA-PAYLOAD-V1` |
| Output | 32-byte symmetric key for AEAD |
| Library | `golang.org/x/crypto/hkdf` |

### Payload Encryption

| Property | Value |
|----------|-------|
| Algorithm | **XChaCha20-Poly1305** (AEAD) |
| Nonce size | 24 bytes |
| Tag size | 16 bytes |
| Mode | Detached (ciphertext + tag stored separately) |
| AAD | Canonicalized artifact header + `artifactHash` |
| Library | `golang.org/x/crypto/chacha20poly1305` (`NewX`) |

### Artifact Hashing

| Property | Value |
|----------|-------|
| Algorithm | **SHA-256** |
| Input | JCS-canonicalized artifact **without** `artifactHash` field |
| Output | 64 lowercase hex characters |
| Library | Go standard library `crypto/sha256` |

### Decision Signing

| Property | Value |
|----------|-------|
| Algorithm | **Ed25519** |
| Signed object | `DecisionSignable` (canonical JSON bytes) |
| Output | 64-byte raw signature, base64url encoded |
| Library | Go standard library `crypto/ed25519` |

---

## Running the Demo

### Prerequisites

- Go 1.26+

### Build

```bash
cd src/go
go build ./cmd/harp-executor/
go build ./cmd/harp-approver/
go build ./cmd/harp-enforcer/
```

### Run the 4-Step Flow

All generated files are written to `C:\tmp\harp\` by default.

```bash
# Step 1: Generate MA keys
go run ./cmd/harp-approver/

# Step 2: Build encrypted artifact
go run ./cmd/harp-executor/

# Step 3: Decrypt & approve (type 'y' to allow, 'n' to deny)
go run ./cmd/harp-approver/

# Step 4: Verify signature & enforce
go run ./cmd/harp-enforcer/
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

Run the enforcer a second time without re-approving. The nonce journal blocks reuse.

```bash
# After a successful Step 4:
go run ./cmd/harp-enforcer/
# ❌ REJECT: Replay detected (nonce already seen)
```

### 2. Deny Decision

When prompted in Step 3, type `n` to deny the request.

```bash
go run ./cmd/harp-approver/
# Approve? (y/n): n

go run ./cmd/harp-enforcer/
# 🔴 ENFORCER RESULT: DENY (exit code 2)
```

### 3. Tampered Artifact (Hash Mismatch)

After Step 2, manually edit `artifact-wire.json` — change any header field (e.g. `repoRef`). The approver will detect the hash mismatch.

```bash
go run ./cmd/harp-executor/
# Edit C:\tmp\harp\artifact-wire.json → change "repoRef" to "repo:opaque:TAMPERED"

go run ./cmd/harp-approver/
# ❌ Hash mismatch. Refuse.
```

### 4. Tampered Decision (Signature Fails)

After Step 3, edit `decision.json` — change the `decision` field from `"allow"` to `"deny"` without re-signing. The enforcer will detect the invalid signature.

```bash
# Edit C:\tmp\harp\decision.json → change "allow" to "deny"

go run ./cmd/harp-enforcer/
# ❌ REJECT: Invalid signature
```

### 5. Expired Artifact or Decision

After Step 3, wait longer than the TTL (5 minutes for the artifact, 10 minutes for the decision).

```bash
# Wait 5+ minutes after Step 2, then:
go run ./cmd/harp-enforcer/
# ❌ REJECT: Artifact expired at ...
```

### 6. Wrong Key (Key Mismatch)

Delete `ma-keys.json` to regenerate keys, then try to enforce the old decision signed with the previous key.

```bash
rm C:\tmp\harp\ma-keys.json
go run ./cmd/harp-approver/      # Generates NEW keys

go run ./cmd/harp-enforcer/
# ❌ REJECT: Invalid signature
```

### 7. Binding Mismatch (requestId / repoRef)

Manually edit `decision.json` and change `requestId` to a different value.

```bash
# Edit C:\tmp\harp\decision.json → change requestId

go run ./cmd/harp-enforcer/
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

| Package | Purpose |
|---------|---------|
| `golang.org/x/crypto/curve25519` | X25519 key exchange |
| `golang.org/x/crypto/chacha20poly1305` | XChaCha20-Poly1305 AEAD |
| `golang.org/x/crypto/hkdf` | HKDF-SHA256 key derivation |
| `crypto/ed25519` *(stdlib)* | Ed25519 signing and verification |
| `crypto/sha256` *(stdlib)* | SHA-256 hashing |
| `crypto/rand` *(stdlib)* | Cryptographically secure randomness |
| `encoding/json` *(stdlib)* | JSON marshaling with sorted map keys |

---

## Cross-Language Interoperability

This Go implementation produces **wire-compatible** output with the [C# reference implementation](../csharp/README.md), the [Node.js reference implementation](../node/README.md), the [Python reference implementation](../python/README.md), and the [TypeScript reference implementation](../typescript/README.md). Artifacts encrypted by any implementation can be decrypted by the others, and decisions signed by any can be verified by the others, provided the same key material is used.

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
