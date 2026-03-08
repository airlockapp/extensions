# HARP-PROMPT: Human Authorization & Review Protocol (Prompt Extension)
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Extension)

---

## Abstract

HARP-PROMPT standardizes the representation, integrity protection, and delivery semantics of prompts sent to an AI Agent through a HARP Enforcer. HARP-PROMPT is an OPTIONAL extension to HARP-CORE. It enables interoperable prompt submission, auditability, and enterprise policy hooks while remaining compatible with zero-knowledge gateways.

---

## 1. Conventions and Dependencies

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

This document depends on:

- HARP-CORE canonicalization rules
- HARP-CORE Envelope (optional transport wrapper)
- HARP-CORE error code semantics

---

## 2. Motivation and Scope

### 2.1 Motivation

Prompts are control-plane inputs that influence AI Agent output. In enterprise settings, prompts may contain sensitive information and may need to be governed and audited. Tool vendors currently implement prompt injection and logging inconsistently.

HARP-PROMPT defines:

- A standard prompt artifact (`prompt.send`)
- Deterministic hashing (`promptHash`)
- Delivery acknowledgement (`prompt.ack`)
- Policy hook points for approval, rate limits, and restrictions

### 2.2 Non-Goals

HARP-PROMPT does NOT define:

- Chat transcript streaming or replication
- Agent memory introspection
- Tool-specific UI automation requirements

---

## 3. Actors and Trust Model

Actors are inherited from HARP-CORE.

- AI Agent consumes prompt content.
- HARP Enforcer constructs, hashes, and delivers prompts.
- Mobile Approver MAY be used to originate prompts or to enforce approvals by policy.
- Gateway (if present) MUST be treated as untrusted for plaintext.

E2E encryption of prompt contents is RECOMMENDED where the gateway is used.

---

## 4. Data Model

### 4.1 prompt.send Artifact

`artifactType` MUST be `prompt.send`.

Required fields:
- `requestId`
- `artifactType`
- `createdAt`
- `target`
- `text`
- `promptHashAlg`
- `promptHash`

Optional fields:
- `sessionId`
- `repoRef`
- `metadata`
- `extensions`

Normative JSON Schema: `harp-prompt-prompt-send.schema.json`

### 4.2 PromptSignable Form

`promptHash` MUST be computed over the canonical JSON bytes of the prompt object with:
- `promptHash` omitted
- all other present fields included

### 4.3 Hash Algorithm

`promptHashAlg` MUST be `"SHA-256"`.
`promptHash` MUST be 64 lowercase hex characters.

---

## 5. Delivery Semantics

### 5.1 Idempotency

The HARP Enforcer MUST treat `(requestId, promptHash)` as an idempotency key.

If the same pair is received again, the Enforcer MUST NOT deliver duplicate prompts to the AI Agent and SHOULD return/emit `prompt.ack` with status `delivered` (or `queued` if still pending).

If `requestId` matches but `promptHash` differs, the Enforcer MUST reject with `HARP_ERR_HASH_MISMATCH`.

### 5.2 Ordering

HARP-PROMPT does not require global ordering. However:

- Within a `sessionId`, the Enforcer SHOULD preserve submission order best-effort.
- If ordering cannot be preserved (e.g., reconnect), the Enforcer MUST still enforce idempotency and integrity.

### 5.3 Expiration

If an implementation wishes to expire prompts, it MAY add an extension field (e.g., `extensions.harpPrompt.expiresAt`). If present, Enforcer MUST honor it and emit `prompt.ack` status `expired` after expiry.

---

## 6. Policy Hooks (Normative)

The Enforcer MUST expose policy decision points for:

- Allow/deny prompt submission by repoRef/tenant
- Rate limiting (per deviceId, per repoRef, per sessionId)
- Classification-based restrictions (optional; see Section 9)

Default policy (if unspecified):
- Prompts are allowed
- Prompts are audited at metadata level

Enterprises MAY require additional controls, including explicit approval for certain prompt categories. Such approval mechanisms MAY use HARP-CORE Decisions, but HARP-PROMPT does not require them.

---

## 7. Acknowledgement

Implementations SHOULD emit or return an acknowledgement object (`prompt.ack`) after processing a prompt.

Statuses:
- `queued`
- `delivered`
- `rejected`
- `expired`
- `error`

Normative JSON Schema: `harp-prompt-prompt-ack.schema.json`

---

## 8. Error Handling

HARP-PROMPT uses HARP-CORE error codes. Additional recommended codes:

- `HARP_PROMPT_ERR_RATE_LIMIT`
- `HARP_PROMPT_ERR_TARGET_UNSUPPORTED`
- `HARP_PROMPT_ERR_TOO_LARGE`

Where `target` is unsupported, Enforcer SHOULD fail closed and emit `HARP_PROMPT_ERR_TARGET_UNSUPPORTED`.

---

## 9. Security Considerations

- Prompt contents may contain secrets; plaintext exposure should be minimized.
- Gateway is untrusted; E2E encryption is RECOMMENDED.
- Integrity is ensured by promptHash; Enforcer MUST verify promptHash prior to delivery.
- UI injection is tool-specific; implementers MUST ensure the AI Agent receives exactly the reviewed prompt content.
- Audit logs SHOULD avoid storing full prompt text unless explicitly configured.

---

## 10. Test Vectors (Normative)

See `HARP_PROMPT_Test_Vectors_v0_2.md`.

---

## Appendix A: Implementation Guidance (Non-Normative)

- Prefer multi-line prompt support in HE UX.
- Use size limits and safe handling for very long prompts.
- When using a gateway, consider payload chunking at the transport layer (out of scope here).
