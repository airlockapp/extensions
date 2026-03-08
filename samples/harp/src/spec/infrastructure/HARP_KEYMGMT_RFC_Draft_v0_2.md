# HARP-KEYMGMT: Cryptographic Key Management Specification
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Standards Track)

---

## Abstract

HARP-KEYMGMT defines normative requirements for cryptographic key provisioning, device binding, rotation, revocation, storage, and trust establishment for HARP-compliant systems.

This specification covers:

- Key types and roles
- Device identity binding
- Key generation requirements
- Key storage requirements
- Public key distribution
- Key rotation procedures
- Revocation model
- Trust anchors
- Multi-device and multi-tenant considerations
- Forward compatibility and cryptographic agility

This document is REQUIRED for enterprise-grade HARP deployments.

---

## 1. Conventions

Normative language follows RFC 2119.

This specification depends on:

- HARP-CORE v0.2
- HARP-TRANSPORT v0.2

---

## 2. Key Roles

HARP defines the following key roles:

### 2.1 Mobile Approver Signing Key (MA-SK)

- Algorithm: Ed25519 (v0.2)
- Purpose: Sign Decision objects
- Scope: Human authorization authority
- Storage: MUST remain private to the Mobile Approver device

### 2.2 Mobile Approver Public Key (MA-PK)

- Purpose: Verification of Decisions by HARP Enforcer
- Distribution: MUST be securely provisioned to HARP Enforcer

### 2.3 Optional Encryption Keys (E2E)

If end-to-end encryption is used:

- Ephemeral ECDH (X25519 RECOMMENDED)
- Symmetric AEAD (AES-256-GCM or ChaCha20-Poly1305 RECOMMENDED)

Encryption keys MUST NOT replace signature verification.

---

## 3. Key Generation Requirements

### 3.1 Entropy

Keys MUST be generated using a cryptographically secure random number generator.

Minimum entropy requirement:
- 256 bits for private keys

### 3.2 Device Binding

Each Mobile Approver key MUST be bound to a unique device identifier.

Device identifier SHOULD be:

- Randomly generated UUID
- NOT hardware serial number
- NOT personally identifiable information

---

## 4. Key Storage Requirements

### 4.1 Mobile Approver

Private keys MUST be stored using:

- OS-provided secure enclave or hardware-backed keystore where available
- Secure Keychain (iOS/macOS)
- Android Keystore (StrongBox if available)
- TPM-backed store (Windows)

Private keys MUST NOT be exportable in plaintext.

### 4.2 HARP Enforcer

Public keys MUST be stored in:

- OS-protected configuration storage
- Encrypted configuration store
- Trusted keystore where available

Public keys MUST be integrity-protected.

---

## 5. Public Key Provisioning

### 5.1 Initial Trust Establishment

Provisioning MUST occur via one of:

- QR code scanning
- Out-of-band secure channel
- Mutual TLS bootstrapping
- Signed provisioning tokens

The HARP Enforcer MUST record:

- signerKeyId
- public key
- deviceId
- creation timestamp

### 5.2 Key Fingerprint

Key fingerprint SHOULD be SHA-256 over raw public key bytes (hex or base64url encoded).

Fingerprint SHOULD be displayed during pairing.

---

## 6. Key Rotation

### 6.1 Rotation Triggers

Keys MUST be rotated upon:

- Device compromise
- Lost device
- Suspected key leakage
- Scheduled rotation (RECOMMENDED annually)

### 6.2 Rotation Procedure

1. Generate new keypair.
2. Provision new public key to HARP Enforcer.
3. Mark old key as deprecated.
4. Revoke old key after safe transition period.

During transition, Enforcer MAY accept both keys.

---

## 7. Revocation Model

### 7.1 Revocation Triggers

- Device reported lost or stolen
- Insider threat detection
- Policy violation

### 7.2 Revocation Enforcement

HARP Enforcer MUST maintain a revocation list.

If signerKeyId is revoked:
- All incoming Decisions from that key MUST be rejected.

Revocation MUST take effect immediately.

---

## 8. Multi-Device and Multi-User Support

HARP MUST support:

- Multiple Mobile Approvers per tenant
- Role-based authorization mapping
- Quorum approval (future extension)

Each key MUST have a unique signerKeyId.

---

## 9. Trust Anchors

Enterprise deployments MAY define:

- Root signing authority
- Certificate-based identity binding
- PKI integration

HARP-KEYMGMT does not mandate PKI but MUST allow integration.

---

## 10. Cryptographic Agility

Future versions MAY introduce:

- Ed448
- ECDSA P-256
- Post-quantum signature algorithms

Implementations SHOULD design signer metadata to include algorithm identifiers.

---

## 11. Secure Backup and Recovery

Private keys SHOULD NOT be backed up in plaintext.

If backup is required:

- Use encrypted backup with strong passphrase
- Use hardware-backed secure export where available

Recovery procedures MUST include re-validation by HARP Enforcer.

---

## 12. Audit Requirements

HARP Enforcer MUST log:

- Key provisioning events
- Rotation events
- Revocation events
- Signature verification failures

Logs SHOULD NOT store private keys or plaintext secrets.

---

## 13. Security Considerations

- Compromise of MA private key compromises authorization authority.
- Compromise of HE public key store may allow rogue key injection.
- Provisioning channel security is critical.
- Key rotation procedures MUST be tested operationally.

---

## 14. Compliance

An implementation is HARP-KEYMGMT compliant if:

- It generates keys securely
- It stores private keys securely
- It enforces revocation
- It supports rotation
- It binds keys to device identity
- It verifies signatures against provisioned public keys

