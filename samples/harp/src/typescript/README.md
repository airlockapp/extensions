# HARP TypeScript Reference Implementation

> **HARP — Human Authorization & Review Protocol**
> Version 0.2 Draft · TypeScript · libsodium

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
| **HARP Enforcer (HE)** | Intercepts actions, builds encrypted artifacts, verifies decisions, gates execution | `harp-executor.ts` (proposer) + `harp-enforcer.ts` (verifier) |
| **Mobile Approver (MA)** | Human-controlled device that reviews artifact content and signs decisions | `harp-approver.ts` |
| **Gateway (GW)** | Optional untrusted relay (not implemented in this demo) | — |

---

## Project Structure

```
src/typescript/
├── package.json
├── tsconfig.json
└── src/
    ├── harp-executor.ts           HE Proposer — builds & encrypts artifacts
    ├── harp-approver.ts           Mobile Approver — generates keys, decrypts, signs
    ├── harp-enforcer.ts           HE Verifier — verifies signatures & enforces
    └── lib/
        ├── models.ts              Interfaces for ArtifactWire, Decision, EncBlob, etc.
        ├── crypto-helpers.ts      Base64url, SHA-256, HKDF, X25519, XChaCha20, Ed25519
        ├── canonical-json.ts      JCS canonicalization (RFC 8785)
        └── nonce-journal.ts       Append-only nonce replay journal
```

---

## TypeScript-Specific Design

This implementation leverages TypeScript features for improved type safety:

| Feature | Usage |
|---------|-------|
| `interface` with `readonly` | All wire types (`ArtifactWire`, `Decision`, `EncBlob`, `MaKeys`) are immutable interfaces |
| Discriminated unions | `decision: "allow" \| "deny"` and `scope: "once" \| "timebox" \| "session"` |
| `never` return type | `fail()` function ensures exhaustive error handling |
| `satisfies` operator | Type-safe JSON serialization in nonce journal |
| `as const` assertions | Payload literals are narrowed to their exact types |
| Private class fields | `#path`, `#active` in `NonceJournalStore` |
| Async `initCrypto()` | Explicit bootstrap instead of top-level await |
| `tsx` runner | Runs TypeScript directly without compilation for development |

---

## Cryptographic Architecture

This implementation uses **libsodium** (via `libsodium-wrappers-sumo`) for XChaCha20-Poly1305, X25519, and Ed25519, with Node.js built-in `crypto` for SHA-256 and HKDF. **RFC 8785 (JCS)** is used for deterministic canonicalization via the `canonicalize` npm package.

### Key Exchange

| Property | Value |
|----------|-------|
| Algorithm | **X25519** |
| Purpose | Derive shared secret between HE (Executor) and MA (Approver) |
| Library | `libsodium-wrappers-sumo` (`crypto_box_keypair`, `crypto_scalarmult`) |
| Export format | Raw 32-byte keys (base64url) |

### Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | **HKDF-SHA256** |
| Salt | 16 random bytes (per-artifact) |
| Info | `HARP-XCHACHA-PAYLOAD-V1` |
| Output | 32-byte symmetric key for AEAD |
| Library | Node.js built-in `crypto.hkdfSync` |

### Payload Encryption

| Property | Value |
|----------|-------|
| Algorithm | **XChaCha20-Poly1305** (AEAD) |
| Nonce size | 24 bytes |
| Tag size | 16 bytes |
| Mode | Detached (ciphertext + tag stored separately) |
| AAD | Canonicalized artifact header + `artifactHash` |
| Library | `libsodium-wrappers-sumo` (`crypto_aead_xchacha20poly1305_ietf_*`) |

> Only the **payload** field of the artifact is encrypted. All header fields remain in plaintext for routing and validation.

### Artifact Hashing

| Property | Value |
|----------|-------|
| Algorithm | **SHA-256** |
| Input | JCS-canonicalized artifact **without** `artifactHash` field |
| Output | 64 lowercase hex characters |
| Library | Node.js built-in `crypto.createHash` |

### Decision Signing

| Property | Value |
|----------|-------|
| Algorithm | **Ed25519** |
| Signed object | `DecisionSignable` (canonical JSON bytes) |
| Output | 64-byte raw signature, base64url encoded |
| Library | `libsodium-wrappers-sumo` (`crypto_sign_detached`, `crypto_sign_verify_detached`) |

---

## Running the Demo

### Prerequisites

- Node.js 18+ (for built-in `crypto.hkdfSync`)
- npm

### Install Dependencies

```bash
cd src/typescript
npm install
```

### Run the 4-Step Flow

All generated files are written to `C:\tmp\harp\` by default. Programs are run via `tsx` (TypeScript Execute), which runs `.ts` files directly without compilation.

```bash
# Step 1: Generate MA keys
npx tsx src/harp-approver.ts

# Step 2: Build encrypted artifact
npx tsx src/harp-executor.ts

# Step 3: Decrypt & approve (type 'y' to allow, 'n' to deny)
npx tsx src/harp-approver.ts

# Step 4: Verify signature & enforce
npx tsx src/harp-enforcer.ts
```

Or use the npm scripts:

```bash
npm run approver     # Step 1 & 3
npm run executor     # Step 2
npm run enforcer     # Step 4
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
{"command":"echo \"hello harp\"","workingDirectory":"/tmp","timeoutSeconds":10}
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
# Remove generated files to start fresh
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
npx tsx src/harp-enforcer.ts
# ❌ REJECT: Replay detected (nonce already seen)
```

### 2. Deny Decision

When prompted in Step 3, type `n` to deny the request.

```bash
npx tsx src/harp-approver.ts
# Approve? (y/n): n

npx tsx src/harp-enforcer.ts
# 🔴 ENFORCER RESULT: DENY (exit code 2)
```

### 3. Tampered Artifact (Hash Mismatch)

After Step 2, manually edit `artifact-wire.json` — change any header field (e.g. `repoRef`). The approver will detect the hash mismatch.

```bash
npx tsx src/harp-executor.ts
# Edit C:\tmp\harp\artifact-wire.json → change "repoRef" to "repo:opaque:TAMPERED"

npx tsx src/harp-approver.ts
# ❌ Hash mismatch. Refuse.
```

### 4. Tampered Decision (Signature Fails)

After Step 3, edit `decision.json` — change the `decision` field from `"allow"` to `"deny"` without re-signing. The enforcer will detect the invalid signature.

```bash
# Edit C:\tmp\harp\decision.json → change "allow" to "deny"

npx tsx src/harp-enforcer.ts
# ❌ REJECT: Invalid signature
```

### 5. Expired Artifact or Decision

After Step 3, wait longer than the TTL (5 minutes for the artifact, 10 minutes for the decision).

```bash
# Wait 5+ minutes after Step 2, then:
npx tsx src/harp-enforcer.ts
# ❌ REJECT: Artifact expired at ...
```

### 6. Wrong Key (Key Mismatch)

Delete `ma-keys.json` to regenerate keys, then try to enforce the old decision signed with the previous key.

```bash
rm C:\tmp\harp\ma-keys.json
npx tsx src/harp-approver.ts      # Generates NEW keys

npx tsx src/harp-enforcer.ts
# ❌ REJECT: Invalid signature
```

### 7. Binding Mismatch (requestId / repoRef)

Manually edit `decision.json` and change `requestId` to a different value.

```bash
# Edit C:\tmp\harp\decision.json → change requestId

npx tsx src/harp-enforcer.ts
# ❌ REJECT: Decision.requestId != Artifact.requestId
```

---

## Files Generated

| File | Generated By | Contents |
|------|-------------|----------|
| `ma-keys.json` | harp-approver.ts (Step 1) | X25519 + Ed25519 keypairs, signerKeyId |
| `artifact-wire.json` | harp-executor.ts (Step 2) | Artifact with encrypted payload + enc blob |
| `decision.json` | harp-approver.ts (Step 3) | Signed allow/deny decision token |
| `nonce-journal.ndjson` | harp-enforcer.ts (Step 4) | Append-only replay protection journal |

---

## npm Dependencies

| Package | Purpose |
|---------|---------|
| `libsodium-wrappers-sumo` | X25519, XChaCha20-Poly1305, Ed25519 |
| `canonicalize` | RFC 8785 JSON Canonicalization Scheme (JCS) |
| `tsx` (dev) | Run TypeScript files directly without compilation |
| `typescript` (dev) | TypeScript compiler for type checking |

> **Note:** `libsodium-wrappers-sumo` is loaded via `createRequire()` (CJS) due to a broken ESM distribution on Node.js 22. This is transparent to consumers.

---

## Cross-Language Interoperability

This TypeScript implementation produces **wire-compatible** output with the [C# reference implementation](../csharp/README.md), the [Node.js reference implementation](../node/README.md), and the [Python reference implementation](../python/README.md). Artifacts encrypted by any implementation can be decrypted by the others, and decisions signed by any can be verified by the others, provided the same key material is used.

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
