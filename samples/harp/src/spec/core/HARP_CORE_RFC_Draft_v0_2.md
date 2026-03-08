# HARP-CORE: Human Authorization & Review Protocol (Core)
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Standards Track)

---

## Abstract

HARP-CORE defines a cryptographically verifiable human authorization layer for autonomous AI agent actions. It standardizes:

1. Deterministic artifact canonicalization and hashing.
2. Signed decision tokens binding approvals/denials to exact artifacts.
3. Mandatory enforcement requirements for a local control boundary (the HARP Enforcer).
4. Interoperability primitives: schemas, error codes, state machines, and test vectors.

---

## 1. Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

### 1.1 Actors

- **AI Agent**: Produces candidate actions (plans, patches, commands, checkpoints).
- **HARP Enforcer (HE)**: Mandatory enforcement boundary. Intercepts actions, produces artifacts, requests authorization, verifies Decisions, and gates execution.
- **Mobile Approver (MA)**: Human-controlled device that reviews artifact content and signs Decisions.
- **Gateway (GW)**: Optional relay. GW MUST be treated as untrusted for plaintext and MUST be compatible with zero-knowledge routing.

### 1.2 Objects

- **Artifact**: Deterministic, canonical representation of an action that requires review.
- **artifactHash**: SHA-256 digest of an Artifact’s canonical bytes (computed over the signable form defined in Section 5.2).
- **Decision**: Signed authorization/denial bound to an artifactHash.
- **DecisionSignable**: The Decision object excluding the `signature` field; canonicalized and signed.
- **Envelope**: Transport wrapper for artifacts, decisions, and errors.

---

## 2. Goals and Non-Goals

### 2.1 Goals

HARP-CORE MUST provide:

- Binding between what was reviewed and what is executed.
- Replay resistance (nonce + expiry + cache).
- Deterministic hashing across platforms.
- Compatibility with untrusted relays (GW).

### 2.2 Non-Goals

HARP-CORE does not specify:

- User interface requirements for review.
- Transport bindings (HTTP, WebSocket, etc.) beyond the optional Envelope.
- Key provisioning, rotation, attestation, or revocation (operationally REQUIRED, but out of scope here).

---

## 3. Threat Model

HARP-CORE targets the following threats:

- **T1 Substitution**: swap reviewed content with different content before execution.
- **T2 Replay**: reuse an old approval to authorize a new or delayed action.
- **T3 Relay compromise**: GW observes/modifies/forges traffic.
- **T4 UI deception**: MA sees content that differs from what HE will execute.
- **T5 Enforcement bypass**: execute action without passing through HE.

Mitigations:

- Canonicalization + artifactHash binding (T1, T4).
- Decision signature + expiration + nonce + replay cache (T2).
- Signature verification always required; E2E encryption recommended (T3).
- HE gating is mandatory for compliance (T5).

---

## 4. Serialization and Canonicalization

### 4.1 Canonical JSON Profile

HARP-CORE uses a strict canonical JSON profile:

1. Serialize using UTF-8.
2. Object keys MUST be sorted lexicographically (Unicode code points).
3. Separators MUST be exactly `,` and `:` (no whitespace).
4. No trailing newline.
5. Strings MUST be valid JSON strings; escape sequences MUST be normalized by the JSON serializer.
6. Numeric values:
   - Integers are permitted.
   - Floating point values are discouraged due to platform reformatting risk.
   - If non-integer precision is required, represent such values as strings.

Implementations MAY use RFC 8785 (JCS) libraries if they produce identical bytes for all inputs.

### 4.2 Canonicalization Failure

If HE detects that it cannot reproduce canonical bytes deterministically for an object, it MUST fail closed and emit `HARP_ERR_CANONICALIZATION`.

---

## 5. Artifact Specification

### 5.1 Artifact Types

HARP-CORE defines:

- `plan.review`
- `task.review`
- `patch.review`
- `command.review`
- `checkpoint.review`

### 5.2 Artifact Signable Form

`artifactHash` MUST be computed over the canonical JSON bytes of the Artifact with:

- `artifactHash` omitted.
- All other present fields included.

If optional fields are present (e.g., `metadata`, `extensions`), they MUST be included in the signable form.

### 5.3 Hash Algorithm

`artifactHashAlg` MUST be `"SHA-256"`.
`artifactHash` MUST be 64 lowercase hex characters.

### 5.4 Expiration

Artifacts MUST include `expiresAt`. HE MUST treat an Artifact as invalid after `expiresAt` (subject to configured clock skew; RECOMMENDED 60 seconds).

---

## 6. Decision Specification

### 6.1 DecisionSignable Form

DecisionSignable is the Decision object excluding `signature`. The signature input MUST be the canonical JSON bytes of DecisionSignable.

### 6.2 Signature Algorithm

`sigAlg` MUST be `"Ed25519"` in v0.2.

The signature MUST be the raw 64-byte Ed25519 signature encoded as base64url without padding.

### 6.3 Validation Rules

HE MUST validate:

1. Signature verifies over DecisionSignable canonical bytes.
2. Decision `expiresAt` not exceeded (accounting for skew).
3. Decision `artifactHash` equals locally computed artifactHash.
4. Replay protection checks pass (Section 7).
5. Scope constraints pass (Section 7).

If any check fails, HE MUST deny execution.

---

## 7. Scope and Replay Protection

### 7.1 Scopes

- **once**: Decision is single-use for (requestId, artifactHash).
- **timebox**: Decision permits execution until `expiresAt` for the specific artifactHash; HE MUST still prevent multi-use unless explicitly allowed by policy.
- **session**: Decision applies to a session boundary. In v0.2, session binding MUST be expressed via an extension field (e.g., `policyHints.sessionId`). If not present, HE MUST reject with `HARP_ERR_SCOPE`.

### 7.2 Replay Cache

HE MUST maintain a replay cache that records used tuples:
- (requestId, artifactHash)
- (nonce, signerKeyId)
- optionally additional context

Minimum retention MUST be at least until Decision expiration + skew. RECOMMENDED: at least 10 minutes minimum window even for shorter expirations.

---

## 8. Envelope and Error Handling

### 8.1 Envelope

An Envelope MAY be used to transport messages. When used, it MUST conform to `harp-core-envelope.schema.json`.

### 8.2 Error Object

When emitting errors, implementations MUST include:

- `code` (string)
- `message` (string)
- `retryable` (boolean)
- optional `details` (object)

### 8.3 Standard Error Codes

- `HARP_ERR_CANONICALIZATION`
- `HARP_ERR_HASH_MISMATCH`
- `HARP_ERR_SIGNATURE_INVALID`
- `HARP_ERR_EXPIRED`
- `HARP_ERR_REPLAY`
- `HARP_ERR_SCOPE`
- `HARP_ERR_POLICY_DENY`
- `HARP_ERR_TRANSPORT`
- `HARP_ERR_UNSUPPORTED`

---

## 9. Normative State Machine

Per Artifact requestId, HE MUST implement:

States:
- CREATED
- AWAITING_DECISION
- APPROVED
- DENIED
- EXPIRED
- EXECUTED

Transitions:
- CREATED -> AWAITING_DECISION (artifact submitted)
- AWAITING_DECISION -> APPROVED (valid allow Decision)
- AWAITING_DECISION -> DENIED (valid deny Decision)
- AWAITING_DECISION -> EXPIRED (artifact expires)
- APPROVED -> EXECUTED (action executed once per scope rules)
- APPROVED -> EXPIRED (Decision expires before execution)

HE MUST NOT execute in any state except APPROVED.

---

## 10. Security Considerations

- HE compromise can bypass gating. Implementations SHOULD harden HE (code signing, least privilege, OS key store).
- MA compromise permits unauthorized approvals; operational key rotation and device revocation are REQUIRED.
- GW is untrusted; signatures MUST be verified even when E2E encryption is used.
- Canonicalization bugs are fatal; implementers MUST run the provided test vectors.

---

## 11. Artifacts

### 11.1 JSON Schemas (Normative)

- `harp-core-artifact.schema.json`
- `harp-core-decision.schema.json`
- `harp-core-envelope.schema.json`

### 11.2 Test Vectors (Normative)

See `HARP_CORE_Test_Vectors_v0_2.md`.

---

## Appendix A: Implementation Guidance (Non-Normative)

- Prefer ULID for requestId/sessionId for traceability.
- Keep `repoRef` opaque (avoid leaking repo URLs to GW).
- Use monotonic clocks where possible for expiry evaluation.
- **Metadata layering:** HARP-CORE defines an optional `metadata` field on the Artifact object (Section 5.2). When present, this field is included in the `artifactHash` computation and travels inside the encrypted payload. Separately, the HARP Gateway defines envelope-level `body.metadata` (see HARP-GW §6.3) for routing and display purposes. These are **different fields at different layers** — core artifact `metadata` is integrity-protected and encrypted, while gateway envelope `metadata` is cleartext and subject to the Gateway's forwarding policy.
- **Display-safe metadata:** To provide human-friendly context to Approver applications without leaking `repoRef`, use display-safe metadata keys such as `workspaceName` and `repoName` in the gateway envelope (see HARP-GW §6.4 Well-Known Metadata Keys).
