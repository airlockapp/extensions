# HARP-COMPLIANCE: Compliance & Interoperability Test Suite Specification
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Conformance & Interoperability)

---

## Abstract

HARP-COMPLIANCE defines formal conformance requirements and interoperability testing procedures for:

- HARP-CORE
- HARP-PROMPT
- HARP-SESSION
- HARP-TRANSPORT
- HARP-KEYMGMT

This document specifies:

- Conformance levels
- Mandatory and optional feature matrices
- Required test categories
- Canonicalization validation procedures
- Signature verification test requirements
- Replay and idempotency validation
- Negative test cases
- Interoperability certification criteria

This document is REQUIRED for vendors claiming HARP compliance.

---

# 1. Conformance Levels

Implementations MUST declare one of the following:

## 1.1 Core-Level Compliance

Implements:
- HARP-CORE
- HARP-KEYMGMT

## 1.2 Extended Compliance

Implements:
- HARP-CORE
- HARP-PROMPT
- HARP-SESSION
- HARP-TRANSPORT
- HARP-KEYMGMT

## 1.3 Enterprise Compliance

Implements:
- All above
- mTLS support
- Key rotation enforcement
- Revocation enforcement
- Rate limiting
- Audit logging

---

# 2. Required Test Categories

All compliant implementations MUST pass the following categories.

## 2.1 Canonicalization Tests

- Verify deterministic JSON serialization.
- Validate exact byte match against official test vectors.
- Confirm hash consistency across platforms.

Failure condition:
- Hash mismatch for official test vector.

---

## 2.2 Signature Verification Tests

- Validate correct Ed25519 verification.
- Reject modified payload with valid signature.
- Reject modified signature.
- Reject signature with wrong public key.

Failure condition:
- Acceptance of invalid signature.

---

## 2.3 Replay Protection Tests

- Re-submit identical Decision with same nonce.
- Re-submit expired Decision.
- Re-submit Decision with mismatched artifactHash.

Failure condition:
- Execution allowed under replay conditions.

---

## 2.4 Expiration Enforcement

- Validate artifact expiration enforcement.
- Validate Decision expiration enforcement.
- Validate snapshot expiration if implemented.

Failure condition:
- Execution after expiration.

---

## 2.5 Idempotency Tests

- Re-submit prompt.send with same requestId + hash.
- Re-submit session.snapshot with identical snapshotId + hash.

Expected behavior:
- No duplicate processing.
- Consistent acknowledgement.

Failure condition:
- Duplicate execution.

---

## 2.6 Schema Validation

- Reject payload missing required fields.
- Reject unknown enum values.
- Reject malformed JSON.

Failure condition:
- Acceptance of invalid schema input.

---

## 2.7 Transport Tests

- Validate correct HTTP status mapping.
- Validate WebSocket framing.
- Validate TLS enforcement.
- Validate rejection of plaintext HTTP.

Failure condition:
- Acceptance over insecure transport.

---

## 2.8 Key Management Tests

- Validate secure key provisioning.
- Validate key rotation procedure.
- Validate revocation enforcement.
- Validate signature rejection after revocation.

Failure condition:
- Acceptance of revoked key.

---

## 2.9 Gateway Metadata Forwarding Tests

- Verify routing-only metadata keys (`routingToken`, `approverId`, `tenantId`) are stripped from Approval Request envelopes (HARP-GW §6.3).
- Verify display-safe metadata keys (`workspaceName`, `repoName`) are forwarded into Approval Request body.
- Verify that if no display-safe fields are present, metadata MAY be omitted entirely.

Failure condition:
- Routing-only metadata present in delivered Approval Request.

---

## 2.10 Exchange Withdraw Tests

- Verify withdrawal of a PendingApproval exchange transitions to Withdrawn state.
- Verify withdrawal is rejected (409 Conflict) for exchanges in terminal states (Decided, Expired, Withdrawn).
- Verify related Approver inbox items are removed upon withdrawal.

Failure condition:
- Withdrawal accepted for terminal-state exchange.
- Inbox items remain after successful withdrawal.

---

## 2.11 Presence Tests

- Verify online/offline presence transitions on WebSocket connect/disconnect.
- Verify presence TTL-based automatic expiry.
- Verify hello message initializes presence record with capabilities and metadata.
- Verify presence does not affect routing correctness.

Failure condition:
- Presence status affects Decision delivery.

---

## 2.12 Pairing Tests

- Verify pairing code expiry after TTL (RECOMMENDED: 10 minutes).
- Verify single-use enforcement (reject second use of same code).
- Verify routing token generation upon successful pairing.
- Verify 409 Conflict on double-complete.

Failure condition:
- Pairing code reuse accepted.
- Routing token generated for expired session.

---

# 3. Negative Testing Requirements

Implementations MUST include negative tests for:

- Truncated JSON
- Corrupted hash field
- Corrupted signature field
- Future timestamp manipulation
- Invalid algorithm identifiers
- Oversized payloads

Systems MUST fail closed.

---

# 4. Interoperability Matrix

Vendors MUST test interoperability against:

- At least one independent HARP Enforcer implementation
- At least one independent Mobile Approver implementation

Test scenarios:

- Cross-vendor Decision verification
- Cross-vendor prompt.send handling
- Cross-vendor session.snapshot validation

Results MUST be documented.

---

# 5. Certification Requirements

To claim HARP compliance:

- Publish supported specification versions.
- Publish supported algorithms.
- Publish conformance level.
- Pass official test vectors.
- Pass negative test cases.
- Document residual risk acknowledgement.

Certification MAY be:

- Self-attested
- Third-party audited
- Community-reviewed

---

# 6. Version Compatibility Testing

Implementations MUST:

- Reject unsupported major versions.
- Support backward-compatible minor versions where feasible.
- Log version mismatch errors.

---

# 7. Automated Test Suite Guidance

An official test suite SHOULD include:

- Canonical test vector runner
- Signature validation harness
- Replay attack simulator
- Expiration simulator
- Schema fuzz tester

Implementations SHOULD integrate these tests in CI pipelines.

---

# 8. Audit Requirements

Compliant systems MUST log:

- Signature failures
- Replay rejections
- Revocation enforcement
- Transport security violations

Logs MUST be integrity-protected.

---

# 9. Compliance Declaration Format

A compliant implementation SHOULD publish:

{
  "harpVersion": "0.2",
  "conformanceLevel": "Enterprise",
  "algorithms": ["Ed25519", "SHA-256"],
  "transport": ["HTTPS", "WSS"],
  "mTLS": true
}

---

# 10. Security Considerations

Testing does not guarantee absence of vulnerabilities.
Operational security and code audits remain REQUIRED.

---

# 11. Compliance Criteria Summary

An implementation is HARP-COMPLIANCE conformant if:

- It passes all mandatory tests.
- It enforces fail-closed behavior.
- It implements required cryptographic primitives.
- It enforces replay protection.
- It validates schemas strictly.
- It enforces TLS.

