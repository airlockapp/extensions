# HARP Python Reference Implementation

> **HARP — Human Authorization & Review Protocol**
> Version 0.2 Draft · Python 3.10+ · PyNaCl

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
| **HARP Enforcer (HE)** | Intercepts actions, builds encrypted artifacts, verifies decisions, gates execution | `harp_executor.py` (proposer) + `harp_enforcer.py` (verifier) |
| **Mobile Approver (MA)** | Human-controlled device that reviews artifact content and signs decisions | `harp_approver.py` |
| **Gateway (GW)** | Optional untrusted relay (not implemented in this demo) | — |

---

## Project Structure

```
src/python/
├── requirements.txt
├── harp_executor.py           HE Proposer — builds & encrypts artifacts
├── harp_approver.py           Mobile Approver — generates keys, decrypts, signs
├── harp_enforcer.py           HE Verifier — verifies signatures & enforces
└── harp/
    ├── __init__.py
    ├── crypto_helpers.py      Base64url, SHA-256, HKDF, X25519, XChaCha20, Ed25519
    ├── canonical_json.py      JCS canonicalization (RFC 8785)
    └── nonce_journal.py       Append-only nonce replay journal
```

---

## Cryptographic Architecture

This implementation uses **PyNaCl** (Python bindings for libsodium) for XChaCha20-Poly1305, X25519, and Ed25519, with the **cryptography** library for HKDF-SHA256. **canonicaljson** is used for deterministic JSON canonicalization compatible with RFC 8785.

### Key Exchange

| Property | Value |
|----------|-------|
| Algorithm | **X25519** |
| Purpose | Derive shared secret between HE (Executor) and MA (Approver) |
| Library | `PyNaCl` (`nacl.bindings.crypto_box_keypair`, `nacl.bindings.crypto_scalarmult`) |
| Export format | Raw 32-byte keys (base64url) |

### Key Derivation

| Property | Value |
|----------|-------|
| Algorithm | **HKDF-SHA256** |
| Salt | 16 random bytes (per-artifact) |
| Info | `HARP-XCHACHA-PAYLOAD-V1` |
| Output | 32-byte symmetric key for AEAD |
| Library | `cryptography` (`cryptography.hazmat.primitives.kdf.hkdf.HKDF`) |

### Payload Encryption

| Property | Value |
|----------|-------|
| Algorithm | **XChaCha20-Poly1305** (AEAD) |
| Nonce size | 24 bytes |
| Tag size | 16 bytes |
| Mode | Detached (ciphertext + tag stored separately) |
| AAD | Canonicalized artifact header + `artifactHash` |
| Library | `PyNaCl` (`nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*`) |

> Only the **payload** field of the artifact is encrypted. All header fields remain in plaintext for routing and validation.

### Artifact Hashing

| Property | Value |
|----------|-------|
| Algorithm | **SHA-256** |
| Input | JCS-canonicalized artifact **without** `artifactHash` field |
| Output | 64 lowercase hex characters |
| Library | Python built-in `hashlib.sha256` |

### Decision Signing

| Property | Value |
|----------|-------|
| Algorithm | **Ed25519** |
| Signed object | `DecisionSignable` (canonical JSON bytes) |
| Output | 64-byte raw signature, base64url encoded |
| Library | `PyNaCl` (`nacl.signing.SigningKey`, `nacl.signing.VerifyKey`) |

---

## Artifact Flow (Step by Step)

The demo follows a 4-step flow that exercises the full HARP-CORE lifecycle:

### Step 1 — Generate MA Keys (`harp_approver.py`, first run)

```
harp_approver.py
    │
    ├── Generate X25519 keypair (for payload decryption)
    ├── Generate Ed25519 keypair (for decision signing)
    ├── Derive signerKeyId
    └── Write ma-keys.json
```

**Output:** `ma-keys.json` containing both public and private key material.

### Step 2 — Build & Encrypt Artifact (`harp_executor.py`)

```
harp_executor.py
    │
    ├── Load MA public X25519 key from ma-keys.json
    ├── Build plaintext artifact (command.review)
    │     payload: { command: "echo \"hello harp\"", ... }
    │
    ├── Compute artifactHash:
    │     1. Serialize artifact WITHOUT artifactHash field
    │     2. JCS-canonicalize
    │     3. SHA-256 → 64 hex chars
    │
    ├── Key agreement + encryption:
    │     1. Generate ephemeral X25519 keypair (HE)
    │     2. crypto_scalarmult(hePriv, maPub) → shared secret
    │     3. HKDF-SHA256(shared, salt, info) → 32-byte AEAD key
    │     4. XChaCha20-Poly1305 encrypt(key, nonce, AAD, payload)
    │
    └── Write artifact-wire.json
```

**Output:** `artifact-wire.json` with encrypted payload and `enc` blob containing all decryption parameters.

### Step 3 — Decrypt, Verify & Sign Decision (`harp_approver.py`, second run)

```
harp_approver.py
    │
    ├── Load MA private keys from ma-keys.json
    ├── Parse artifact-wire.json
    │
    ├── Decrypt payload:
    │     1. crypto_scalarmult(maPriv, heEphPub) → same shared secret
    │     2. HKDF-SHA256(shared, salt, info) → same 32-byte AEAD key
    │     3. XChaCha20-Poly1305 decrypt → plaintext
    │
    ├── Verify artifactHash (JCS → SHA-256 → compare)
    ├── Display payload to human for review
    ├── Prompt: "Approve? (y/n)"
    │
    ├── Sign: Ed25519(maSignPriv, JCS(DecisionSignable))
    ├── Self-verify signature
    └── Write decision.json
```

**Output:** `decision.json` with cryptographic signature binding the approval to the exact artifact.

### Step 4 — Verify & Enforce (`harp_enforcer.py`)

```
harp_enforcer.py
    │
    ├── Load MA public Ed25519 key from ma-keys.json
    ├── Parse artifact-wire.json and decision.json
    │
    ├── Binding checks:
    │     ✓ decision.requestId == artifact.requestId
    │     ✓ decision.repoRef == artifact.repoRef
    │     ✓ decision.artifactHash == artifact.artifactHash
    │
    ├── Expiry checks:
    │     ✓ Now < artifact.expiresAt
    │     ✓ Now < decision.expiresAt
    │
    ├── Signature verification:
    │     ✓ Ed25519.Verify(maPub, JCS(DecisionSignable), signature)
    │
    ├── Replay protection (scope=once):
    │     ✓ Check nonce:artifactHash not seen before
    │     ✓ Record in nonce-journal.ndjson
    │
    └── Enforce:
          decision == "allow" → 🟢 ALLOW (exit 0)
          decision == "deny"  → 🔴 DENY  (exit 2)
```

**Output:** Enforcement result. `nonce-journal.ndjson` updated for replay protection.

---

## Running the Demo

### Prerequisites

- Python 3.10+
- pip

### Install Dependencies

```bash
cd src/python
pip install -r requirements.txt
```

### Run the 4-Step Flow

All generated files are written to `C:\tmp\harp\` by default.

```bash
# Step 1: Generate MA keys
python harp_approver.py

# Step 2: Build encrypted artifact
python harp_executor.py

# Step 3: Decrypt & approve (type 'y' to allow, 'n' to deny)
python harp_approver.py

# Step 4: Verify signature & enforce
python harp_enforcer.py
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
python harp_enforcer.py
# ❌ REJECT: Replay detected (nonce already seen)
```

### 2. Deny Decision

When prompted in Step 3, type `n` to deny the request.

```bash
python harp_approver.py
# Approve? (y/n): n

python harp_enforcer.py
# 🔴 ENFORCER RESULT: DENY (exit code 2)
```

### 3. Tampered Artifact (Hash Mismatch)

After Step 2, manually edit `artifact-wire.json` — change any header field (e.g. `repoRef`). The approver will detect the hash mismatch.

```bash
python harp_executor.py
# Edit C:\tmp\harp\artifact-wire.json → change "repoRef" to "repo:opaque:TAMPERED"

python harp_approver.py
# ❌ Hash mismatch. Refuse.
```

### 4. Tampered Decision (Signature Fails)

After Step 3, edit `decision.json` — change the `decision` field from `"allow"` to `"deny"` without re-signing. The enforcer will detect the invalid signature.

```bash
# Edit C:\tmp\harp\decision.json → change "allow" to "deny"

python harp_enforcer.py
# ❌ REJECT: Invalid signature
```

### 5. Expired Artifact or Decision

After Step 3, wait longer than the TTL (5 minutes for the artifact, 10 minutes for the decision).

```bash
# Wait 5+ minutes after Step 2, then:
python harp_enforcer.py
# ❌ REJECT: Artifact expired at ...
```

### 6. Wrong Key (Key Mismatch)

Delete `ma-keys.json` to regenerate keys, then try to enforce the old decision signed with the previous key.

```bash
rm C:\tmp\harp\ma-keys.json
python harp_approver.py      # Generates NEW keys

python harp_enforcer.py
# ❌ REJECT: Invalid signature
```

### 7. Binding Mismatch (requestId / repoRef)

Manually edit `decision.json` and change `requestId` to a different value.

```bash
# Edit C:\tmp\harp\decision.json → change requestId

python harp_enforcer.py
# ❌ REJECT: Decision.requestId != Artifact.requestId
```

---

## Files Generated

| File | Generated By | Contents |
|------|-------------|----------|
| `ma-keys.json` | harp_approver.py (Step 1) | X25519 + Ed25519 keypairs, signerKeyId |
| `artifact-wire.json` | harp_executor.py (Step 2) | Artifact with encrypted payload + enc blob |
| `decision.json` | harp_approver.py (Step 3) | Signed allow/deny decision token |
| `nonce-journal.ndjson` | harp_enforcer.py (Step 4) | Append-only replay protection journal |

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
  "requestId": "<UUID>",
  "artifactType": "command.review",
  "repoRef": "repo:opaque:demo",
  "createdAt": "2026-02-24T06:55:00+00:00",
  "expiresAt": "2026-02-24T07:00:00+00:00",
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
  "expiresAt": "2026-02-24T07:05:00+00:00",
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

## pip Dependencies

| Package | Purpose |
|---------|---------|
| `PyNaCl` | X25519, XChaCha20-Poly1305, Ed25519 (libsodium bindings) |
| `cryptography` | HKDF-SHA256 key derivation |
| `canonicaljson` | Deterministic JSON canonicalization (RFC 8785 compatible) |

> Python built-in `hashlib`, `base64`, and `os.urandom` are used for SHA-256, base64url, and random bytes respectively.

---

## Cross-Language Interoperability

This Python implementation produces **wire-compatible** output with the [C# reference implementation](../csharp/README.md) and the [Node.js reference implementation](../node/README.md). Artifacts encrypted by any implementation can be decrypted by the others, and decisions signed by any can be verified by the others, provided the same key material is used.

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
