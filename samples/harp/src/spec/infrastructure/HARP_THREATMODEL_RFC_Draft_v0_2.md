# HARP-THREATMODEL: Formal Threat Model & Security Analysis
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Security Analysis)

---

## Abstract

This document provides a formal threat model and security analysis for the Human Authorization & Review Protocol (HARP) suite, including:

- HARP-CORE
- HARP-PROMPT
- HARP-SESSION
- HARP-TRANSPORT
- HARP-KEYMGMT

This analysis applies structured threat modeling methodology (STRIDE) and defines:

- Assets
- Trust boundaries
- Attack surfaces
- Threat categories
- Mitigations
- Residual risks
- Operational security requirements

This document is REQUIRED for enterprise-grade adoption and security review.

---

# 1. Methodology

This threat model uses:

- STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Asset-centric modeling
- Trust boundary analysis
- Attack surface decomposition

This document focuses on protocol-level threats and enforcement guarantees.

---

# 2. Assets

The following assets are security-critical:

## 2.1 Authorization Authority

Mobile Approver private signing key (MA-SK)

Compromise impact:
- Unauthorized approvals
- Full loss of human control guarantee

## 2.2 Enforcement Integrity

HARP Enforcer integrity and execution gating logic

Compromise impact:
- Bypass of approval requirement
- Silent execution of malicious actions

## 2.3 Artifact Integrity

Canonicalized artifact representation and artifactHash

Compromise impact:
- Approval bound to incorrect content
- Substitution attacks

## 2.4 Transport Channel

Integrity and authenticity of transported artifacts and Decisions

Compromise impact:
- Replay
- Message injection
- Availability degradation

## 2.5 Audit Logs

Metadata audit records

Compromise impact:
- Loss of forensic traceability
- Repudiation risk

---

# 3. Trust Boundaries

HARP defines the following trust boundaries:

1. Between AI Agent and HARP Enforcer
2. Between HARP Enforcer and Mobile Approver
3. Between HARP components and Gateway
4. Between user and Mobile Approver device

The HARP Enforcer is the primary enforcement boundary.

---

# 4. STRIDE Analysis

## 4.1 Spoofing

Threat:
- Attacker impersonates Mobile Approver.

Mitigation:
- Ed25519 signature verification
- signerKeyId binding
- Secure provisioning
- Revocation enforcement

Residual risk:
- MA private key compromise

---

## 4.2 Tampering

Threat:
- Artifact modified after approval.
- Decision modified in transit.

Mitigation:
- Deterministic canonicalization
- artifactHash binding
- Signature verification
- Hash mismatch rejection

Residual risk:
- Canonicalization implementation flaws

---

## 4.3 Repudiation

Threat:
- User denies approving an action.

Mitigation:
- Cryptographic signature
- Audit logging with timestamp
- Device binding

Residual risk:
- Shared device scenarios

---

## 4.4 Information Disclosure

Threat:
- Gateway inspects artifact content.
- Transport leakage.
- Metadata forwarding misconfiguration leaks routing-only metadata (e.g., `routingToken`, `approverId`) to Approver (see HARP-GW §6.3).
- Presence records expose enforcer connectivity patterns, workspace names, and capabilities.
- Pairing flow reveals enforcer identity and public keys during code resolution.

Mitigation:
- Zero-knowledge compatibility
- Optional E2E encryption
- TLS enforcement
- Gateway MUST strip routing-only metadata before forwarding (HARP-GW §6.3)
- Presence endpoints MUST be scoped by tenant and authenticated
- Pairing codes MUST be short-lived and single-use

Residual risk:
- Metadata leakage through display-safe fields (workspace structure inference)
- Traffic analysis
- Presence observation by authenticated tenant members

---

## 4.5 Denial of Service

Threat:
- Flooding artifact or prompt submissions.
- Replay attempts.
- Presence endpoint flooding.
- Pairing code brute-force attempts.

Mitigation:
- Rate limiting
- Idempotency enforcement
- Replay cache
- Pairing codes with sufficient entropy (RECOMMENDED: 6+ alphanumeric characters)
- Presence TTL-based automatic expiry

Residual risk:
- Large-scale distributed attacks

---

## 4.6 Elevation of Privilege

Threat:
- AI Agent bypasses HARP Enforcer.
- HE compromised.

Mitigation:
- Mandatory enforcement requirement
- OS-level process isolation
- Code signing (recommended)

Residual risk:
- Local privilege escalation outside protocol scope

---

# 5. Attack Trees

## 5.1 Execute Unauthorized Command

Paths:
- Compromise MA private key
- Bypass HE
- Exploit canonicalization flaw
- Replay valid Decision

Mitigations:
- Secure key storage
- Replay cache
- Deterministic hashing
- Expiration enforcement

---

# 6. Gateway Risk Analysis

Gateway is assumed untrusted.

Risks:
- Message delay
- Message reordering
- Message dropping
- Metadata observation
- Metadata forwarding misconfiguration (routing-only fields leaked to Approver)
- Pairing session hijacking (attacker intercepts pairing code)
- Presence metadata observation (enforcer connectivity patterns)

Mitigations:
- Signature validation at HE
- Idempotency
- Replay protection
- Optional E2E encryption
- Gateway MUST strip routing-only metadata per HARP-GW §6.3
- Pairing sessions MUST be short-lived and single-use per HARP-GW §6.6
- Presence endpoints MUST be tenant-scoped and authenticated

---

# 7. Cryptographic Risks

## 7.1 Algorithm Obsolescence

Mitigation:
- Cryptographic agility defined in KEYMGMT
- Algorithm identifier fields

## 7.2 Weak Randomness

Mitigation:
- Secure CSPRNG requirement
- OS-backed key generation

---

# 8. Residual Risk Summary

HARP does NOT mitigate:

- Compromise of Mobile Approver device
- Compromise of HARP Enforcer binary
- Insider threats with valid keys
- OS-level compromise

Operational controls are REQUIRED to mitigate these risks.

---

# 9. Operational Security Requirements

Enterprise deployments SHOULD:

- Use hardware-backed key storage
- Enable mTLS
- Enable rate limiting
- Monitor signature verification failures
- Rotate keys periodically
- Conduct code audits of HARP Enforcer

---

# 10. Security Posture Summary

HARP provides:

- Strong cryptographic authorization binding
- Replay resistance
- Deterministic artifact integrity
- Zero-knowledge compatibility
- Clear enforcement boundary

Security ultimately depends on:

- Key management practices
- Enforcer integrity
- Operational controls

---

# 11. Compliance

An implementation is HARP-THREATMODEL compliant if:

- It documents trust boundaries
- It enforces signature validation
- It enforces replay protection
- It implements secure key storage
- It publishes residual risk acknowledgement

