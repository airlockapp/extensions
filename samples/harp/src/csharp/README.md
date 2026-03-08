# HARP C# Reference Implementation

> **HARP — Human Authorization & Review Protocol**
> Version 0.2 Draft · .NET 10 · NSec Cryptography

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

| Actor | Role | This Solution |
|-------|------|---------------|
| **AI Agent** | Produces candidate actions (plans, patches, commands) | *(implicit — payload is hardcoded in demo)* |
| **HARP Enforcer (HE)** | Intercepts actions, builds encrypted artifacts, verifies decisions, gates execution | `Harp.Executor` (proposer) + `Harp.Enforcer` (verifier) |
| **Mobile Approver (MA)** | Human-controlled device that reviews artifact content and signs decisions | `Harp.Approver` |
| **Gateway (GW)** | Optional untrusted relay (not implemented in this demo) | — |

---

## Solution Structure

```
Harp.Sample.slnx
├── Harp.Common/           Shared models, crypto helpers, nonce journal
│   ├── ArtifactWire.cs        Wire-format artifact (encrypted payload)
│   ├── ArtifactPlain.cs       Plaintext artifact (for hashing)
│   ├── EncBlob.cs             Encryption envelope (KDF, AEAD params)
│   ├── Decision.cs            Signed decision token
│   ├── DecisionSignable.cs    Decision without signature (signing input)
│   ├── CanonicalJson.cs       JCS canonicalization
│   ├── Crypto.cs              Base64url, hashing helpers
│   ├── NsecAead.cs            XChaCha20-Poly1305 AEAD wrapper
│   └── NonceJournalStore.cs   Append-only nonce replay journal
│
├── Harp.Executor/         HE Proposer — builds & encrypts artifacts
│   └── Program.cs
│
├── Harp.Approver/         Mobile Approver — generates keys, decrypts, signs
│   └── Program.cs
│
└── Harp.Enforcer/         HE Verifier — verifies signatures & enforces
    └── Program.cs
```

---

## Cryptographic Architecture

This implementation uses **NSec.Cryptography** exclusively, with **RFC 8785 (JCS)** for deterministic canonicalization.

### Key Exchange

| Property | Value |
|----------|-------|
| Algorithm | **X25519** |
| Purpose | Derive shared secret between HE (Executor) and MA (Approver) |
| Export format | `RawPublicKey` / `RawPrivateKey` (base64url) |

### Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | **HKDF-SHA256** |
| Salt | 16 random bytes (per-artifact) |
| Info | `HARP-XCHACHA-PAYLOAD-V1` |
| Output | 32-byte symmetric key for AEAD |

### Payload Encryption

| Property | Value |
|----------|-------|
| Algorithm | **XChaCha20-Poly1305** (AEAD) |
| Nonce size | 24 bytes |
| Tag size | 16 bytes |
| Mode | Detached (ciphertext + tag stored separately) |
| AAD | Canonicalized artifact header + `artifactHash` |

> Only the **payload** field of the artifact is encrypted. All header fields remain in plaintext for routing and validation.

### Artifact Hashing

| Property | Value |
|----------|-------|
| Algorithm | **SHA-256** |
| Input | JCS-canonicalized artifact **without** `artifactHash` field |
| Output | 64 lowercase hex characters |

### Decision Signing

| Property | Value |
|----------|-------|
| Algorithm | **Ed25519** |
| Signed object | `DecisionSignable` (canonical JSON bytes) |
| Output | 64-byte raw signature, base64url encoded |

---

## Artifact Flow (Step by Step)

The demo follows a 4-step flow that exercises the full HARP-CORE lifecycle:

### Step 1 — Generate MA Keys (`Harp.Approver`, first run)

```
Harp.Approver
    │
    ├── Generate X25519 keypair (for payload decryption)
    ├── Generate Ed25519 keypair (for decision signing)
    ├── Derive signerKeyId
    └── Write ma-keys.json
```

**Output:** `ma-keys.json` containing both public and private key material.

### Step 2 — Build & Encrypt Artifact (`Harp.Executor`)

```
Harp.Executor
    │
    ├── Load MA public X25519 key from ma-keys.json
    ├── Build plaintext artifact (command.review)
    │     payload: { command: "echo \"hello harp\"", workingDirectory: "/tmp", timeoutSeconds: 10 }
    │
    ├── Compute artifactHash:
    │     1. Serialize artifact WITHOUT artifactHash field
    │     2. JCS-canonicalize
    │     3. SHA-256 → 64 hex chars
    │
    ├── Build AAD (bind encryption to artifact identity):
    │     AAD = JCS-canonicalize({ requestId, artifactType, repoRef, ..., artifactHash })
    │
    ├── Key agreement + encryption:
    │     1. Generate ephemeral X25519 keypair (HE)
    │     2. X25519 agree(hePriv, maPub) → shared secret
    │     3. HKDF-SHA256(shared, salt, info) → 32-byte AEAD key
    │     4. XChaCha20-Poly1305 encrypt(key, nonce, AAD, payload) → ciphertext + tag
    │
    └── Write artifact-wire.json (header plaintext, payload encrypted)
```

**Output:** `artifact-wire.json` with encrypted payload and `EncBlob` containing all decryption parameters.

### Step 3 — Decrypt, Verify & Sign Decision (`Harp.Approver`, second run)

```
Harp.Approver
    │
    ├── Load MA private keys from ma-keys.json
    ├── Deserialize artifact-wire.json
    │
    ├── Decrypt payload:
    │     1. X25519 agree(maPriv, heEphPub) → same shared secret
    │     2. HKDF-SHA256(shared, salt, info) → same 32-byte AEAD key
    │     3. XChaCha20-Poly1305 decrypt(key, nonce, AAD, ciphertext||tag) → plaintext
    │
    ├── Verify artifactHash:
    │     1. Reconstruct artifact-without-hash using decrypted payload
    │     2. JCS-canonicalize → SHA-256
    │     3. Compare with artifact's artifactHash
    │
    ├── Display payload to human for review
    ├── Prompt: "Approve? (y/n)"
    │
    ├── Build DecisionSignable:
    │     { requestId, artifactHashAlg, artifactHash, repoRef,
    │       decision: "allow"|"deny", scope: "once",
    │       expiresAt, nonce, sigAlg: "Ed25519", signerKeyId }
    │
    ├── Sign: Ed25519(maSignPriv, JCS-canonicalize(DecisionSignable))
    ├── Self-verify signature
    └── Write decision.json
```

**Output:** `decision.json` with cryptographic signature binding the approval to the exact artifact.

### Step 4 — Verify & Enforce (`Harp.Enforcer`)

```
Harp.Enforcer
    │
    ├── Load MA public Ed25519 key from ma-keys.json
    ├── Deserialize artifact-wire.json and decision.json
    │
    ├── Binding checks:
    │     ✓ decision.requestId == artifact.requestId
    │     ✓ decision.repoRef == artifact.repoRef
    │     ✓ decision.artifactHashAlg == artifact.artifactHashAlg
    │     ✓ decision.artifactHash == artifact.artifactHash
    │
    ├── Expiry checks:
    │     ✓ Now < artifact.expiresAt
    │     ✓ Now < decision.expiresAt
    │
    ├── Signature verification:
    │     ✓ sigAlg == "Ed25519"
    │     ✓ signerKeyId == expected key ID
    │     ✓ Ed25519.Verify(maPub, JCS(DecisionSignable), signature)
    │
    ├── Replay protection (scope=once):
    │     ✓ Check nonce:artifactHash not seen before
    │     ✓ Record in nonce-journal.ndjson
    │     ✓ Compact journal if needed (TTL-based pruning)
    │
    └── Enforce:
          decision == "allow" → 🟢 ALLOW (exit 0)
          decision == "deny"  → 🔴 DENY  (exit 2)
```

**Output:** Enforcement result. `nonce-journal.ndjson` updated for replay protection.

---

## Running the Demo

### Prerequisites

- .NET 10 SDK
- Windows / Linux / macOS

### Build

```bash
cd src/cshrap
dotnet build
```

### Run the 4-Step Flow

All generated files are written to `C:\tmp\harp\` by default.

```bash
# Step 1: Generate MA keys
dotnet run --project Harp.Approver

# Step 2: Build encrypted artifact
dotnet run --project Harp.Executor

# Step 3: Decrypt & approve (type 'y' to allow, 'n' to deny)
dotnet run --project Harp.Approver

# Step 4: Verify signature & enforce
dotnet run --project Harp.Enforcer
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
dotnet run --project Harp.Enforcer
# ❌ REJECT: Replay detected (nonce already seen)
```

### 2. Deny Decision

When prompted in Step 3, type `n` to deny the request.

```bash
dotnet run --project Harp.Approver
# Approve? (y/n): n

dotnet run --project Harp.Enforcer
# 🔴 ENFORCER RESULT: DENY (exit code 2)
```

### 3. Tampered Artifact (Hash Mismatch)

After Step 2, manually edit `artifact-wire.json` — change any header field (e.g. `repoRef`). The approver will detect the hash mismatch.

```bash
dotnet run --project Harp.Executor
# Edit C:\tmp\harp\artifact-wire.json → change "repoRef" to "repo:opaque:TAMPERED"

dotnet run --project Harp.Approver
# ❌ Hash mismatch. Refuse.
```

### 4. Tampered Decision (Signature Fails)

After Step 3, edit `decision.json` — change the `decision` field from `"allow"` to `"deny"` without re-signing. The enforcer will detect the invalid signature.

```bash
# Edit C:\tmp\harp\decision.json → change "allow" to "deny"

dotnet run --project Harp.Enforcer
# ❌ REJECT: Invalid signature
```

### 5. Expired Artifact or Decision

After Step 3, wait longer than the TTL (5 minutes for the artifact, 10 minutes for the decision).

```bash
# Wait 5+ minutes after Step 2, then:
dotnet run --project Harp.Enforcer
# ❌ REJECT: Artifact expired at ...
```

### 6. Wrong Key (Key Mismatch)

Delete `ma-keys.json` to regenerate keys, then try to enforce the old decision signed with the previous key.

```bash
rm C:\tmp\harp\ma-keys.json
dotnet run --project Harp.Approver   # Generates NEW keys

dotnet run --project Harp.Enforcer
# ❌ REJECT: Invalid signature
```

### 7. Binding Mismatch (requestId / repoRef)

Manually edit `decision.json` and change `requestId` to a different value.

```bash
# Edit C:\tmp\harp\decision.json → change requestId

dotnet run --project Harp.Enforcer
# ❌ REJECT: Decision.requestId != Artifact.requestId
```

---

## Files Generated

| File | Generated By | Contents |
|------|-------------|----------|
| `ma-keys.json` | Harp.Approver (Step 1) | X25519 + Ed25519 keypairs, signerKeyId |
| `artifact-wire.json` | Harp.Executor (Step 2) | Artifact with encrypted payload + EncBlob |
| `decision.json` | Harp.Approver (Step 3) | Signed allow/deny decision token |
| `nonce-journal.ndjson` | Harp.Enforcer (Step 4) | Append-only replay protection journal |

---

## Wire Format Reference

### ma-keys.json

```json
{
  "maKxPubRawB64Url":        "<X25519 public key, base64url>",
  "maKxPrivRawB64Url":       "<X25519 private key, base64url>",
  "maEd25519PubRawB64Url":   "<Ed25519 public key, base64url>",
  "maEd25519PrivRawB64Url":  "<Ed25519 private key, base64url>",
  "signerKeyId":             "ma-key-1"
}
```

### artifact-wire.json

```json
{
  "requestId": "<GUID>",
  "artifactType": "command.review",
  "repoRef": "repo:opaque:demo",
  "createdAt": "2026-02-23T15:00:00+00:00",
  "expiresAt": "2026-02-23T15:05:00+00:00",
  "artifactHashAlg": "SHA-256",
  "artifactHash": "<64 lowercase hex chars>",
  "enc": {
    "kdf": "X25519+HKDF-SHA256",
    "encAlg": "XChaCha20-Poly1305",
    "maKxPub": "<MA X25519 public key, base64url>",
    "heKxPub": "<HE ephemeral X25519 public key, base64url>",
    "salt": "<16 bytes, base64url>",
    "info": "HARP-XCHACHA-PAYLOAD-V1",
    "nonce": "<24 bytes, base64url>",
    "ciphertext": "<encrypted payload, base64url>",
    "tag": "<16 bytes, base64url>"
  }
}
```

### decision.json

```json
{
  "requestId": "<same as artifact>",
  "artifactHashAlg": "SHA-256",
  "artifactHash": "<same as artifact>",
  "repoRef": "repo:opaque:demo",
  "decision": "allow",
  "scope": "once",
  "expiresAt": "2026-02-23T15:10:00+00:00",
  "nonce": "<16 bytes, base64url>",
  "sigAlg": "Ed25519",
  "signerKeyId": "ma-key-1",
  "signature": "<64 bytes Ed25519 signature, base64url>"
}
```

---

## Decision Scopes

| Scope | Behavior | Replay Protection |
|-------|----------|-------------------|
| `once` | Single-use for the specific `(requestId, artifactHash)` | Nonce recorded in journal; reuse blocked |
| `timebox` | Valid until `expiresAt` for the specific `artifactHash` | Relies on expiry; nonce recording optional |
| `session` | Valid for the scope of a session (requires `policyHints.sessionId`) | Relies on session boundary + expiry |

---

## Replay Protection

The Enforcer implements append-only nonce journal replay protection:

- **Journal file:** `nonce-journal.ndjson` (newline-delimited JSON)
- **Replay key format:** `nonce:artifactHash`
- **TTL-based pruning:** Entries older than 24 hours are eligible for compaction
- **Periodic compaction:** Triggered when journal exceeds 2 MB
- **Crash tolerant:** Append-only design survives unexpected termination
- **No database dependency:** File-based, self-contained

---

## HARP-CORE Artifact State Machine

Per-request lifecycle enforced by HE:

```
CREATED ───────────────────▶ AWAITING_DECISION
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
               APPROVED          DENIED          EXPIRED
                    │
                    ├──────────────────────────────▶ EXECUTED
                    │
                    └──────────────────────────────▶ EXPIRED
                                              (decision expires
                                               before execution)
```

**Rule:** HE MUST NOT execute in any state except APPROVED.

---

## Threat Mitigations

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **T1 — Substitution** | Swap reviewed content with different content before execution | `artifactHash` binds decision to exact canonical artifact bytes |
| **T2 — Replay** | Reuse an old approval for a new/delayed action | Decision nonce + `expiresAt` + nonce journal cache |
| **T3 — Relay Compromise** | Gateway observes/modifies/forges traffic | E2E encryption (AEAD) + Ed25519 signature verification |
| **T4 — UI Deception** | MA sees different content than HE will execute | Canonical hashing — hash is computed over what HE sends and verified by MA |
| **T5 — Enforcement Bypass** | Execute without passing through HE | HE gating is mandatory; exit codes enforce allow/deny |

---

## NuGet Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `NSec.Cryptography` | Latest | X25519, HKDF-SHA256, XChaCha20-Poly1305, Ed25519 |
| `JsonCanonicalizerNs` | Latest | RFC 8785 JSON Canonicalization Scheme (JCS) |

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

- **Secure key storage** — HSM, OS keychain, or secure enclave instead of JSON files
- **mTLS transport binding** — TLS with mutual certificate authentication
- **Structured logging** — Audit trail for all enforcement decisions
- **Multi-approver quorum** — Require multiple human approvals for critical actions
- **Key rotation** — Automated key lifecycle management
- **Clock skew handling** — Configurable tolerance (RECOMMENDED: 60 seconds)
- **Rate limiting** — Protect MA from DoS via excessive approval requests
- **Revocation enforcement** — CRL or OCSP-like mechanism for compromised keys
