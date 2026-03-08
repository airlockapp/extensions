# HARP – Human Authorization & Review Protocol

Version: 0.2 Draft  
Status: Standards-Grade Draft Suite

---

![title](assets/harp-dark.png)

## Overview

HARP (Human Authorization & Review Protocol) is a cryptographically verifiable authorization and control layer for AI coding agents and autonomous development tools.

HARP ensures:

- Every sensitive AI action is explicitly bound to human approval.
- Approvals are cryptographically signed and verifiable.
- Replay and substitution attacks are prevented.
- Gateways can remain zero-knowledge.
- Cross-vendor interoperability is possible through open standards.

HARP is tool-agnostic and designed for enterprise-grade deployment.

---

# Repository Structure

The repository is organized according to protocol layers and governance boundaries.

```
/core
    HARP-CORE specification
    Core schemas
    Core test vectors

/prompt
    HARP-PROMPT specification
    Prompt schemas
    Prompt test vectors

/session
    HARP-SESSION specification
    Session schemas
    Session test vectors

/gateway
    HARP-GATEWAY RFC Draft specification
    HARP-GATEWAY HTTP Binding specification
    Gateway schemas
    Gateway test vectors
    Gateway examples

/infrastructure
    HARP-TRANSPORT specification
    HARP-KEYMGMT specification
    HARP-THREATMODEL specification
    HARP-COMPLIANCE specification

/governance
    HARP-GOVERNANCE specification

README.md
```

---

# Folder Responsibilities

## /core

Defines the cryptographic authorization foundation:

- Deterministic canonicalization
- Artifact hashing (SHA-256)
- Decision signing (Ed25519)
- Replay protection
- State machine enforcement

This layer is mandatory for all HARP implementations.

---

## /prompt

Defines the prompt control extension:

- prompt.send artifact model
- Prompt integrity hashing
- Idempotency semantics
- Acknowledgement model

Optional extension layer.

---

## /session

Defines session lifecycle and snapshot integrity:

- session.start
- session.status
- session.snapshot
- session.end
- Snapshot hashing

Optional extension layer.

---

## /gateway

Defines the gateway exchange semantics and HTTP transport binding:

- Artifact → Approval Request → Decision → Delivery flow
- Envelope-mandatory framing for all payloads
- REST, SSE, and WebSocket bindings
- Inbox-based delivery model
- Push notification guidance (out-of-band hints)

This layer defines how HARP messages traverse the network between actors.

---

## /infrastructure

Defines operational and security infrastructure:

- HARP-TRANSPORT (HTTP & WebSocket bindings)
- HARP-KEYMGMT (key lifecycle management)
- HARP-THREATMODEL (formal security analysis)
- HARP-COMPLIANCE (conformance & interoperability testing)

These documents define deployment and enterprise requirements.

---

## /governance

Defines protocol evolution and registry control:

- Versioning model
- Artifact type registry
- Error code registry
- Algorithm registry
- Change control process
- Extension lifecycle rules

This ensures long-term interoperability and stability.

---

# Specification Stack

HARP is layered as follows:

Layer 1 – Core Authorization  
Layer 2 – Prompt & Session Extensions  
Layer 3 – Gateway Exchange Semantics  
Layer 4 – Transport Binding  
Layer 5 – Key Management  
Layer 6 – Security & Compliance  
Layer 7 – Governance & Evolution  

---

# Compliance Levels

## Core-Level

- HARP-CORE
- HARP-KEYMGMT

## Extended

- CORE
- PROMPT
- SESSION
- GATEWAY
- TRANSPORT
- KEYMGMT

## Enterprise

- All above
- mTLS support
- Key rotation
- Revocation enforcement
- Rate limiting
- Audit logging

---

# Versioning

HARP follows Semantic Versioning:

MAJOR.MINOR.PATCH

MAJOR – Breaking changes  
MINOR – Backward-compatible additions  
PATCH – Editorial updates only  

Implementations MUST declare supported version.

---

# Interoperability

To claim HARP compliance, implementations MUST:

- Pass official test vectors
- Enforce signature validation
- Enforce replay protection
- Enforce TLS
- Follow governance rules
- Publish supported version and algorithms

Cross-vendor interoperability testing is strongly recommended.

---

# Security Model

HARP provides:

- Cryptographically signed Decisions
- Deterministic artifact hashing
- Replay resistance
- Secure key lifecycle management
- Transport security enforcement

HARP does NOT mitigate:

- Compromised local OS
- Compromised Mobile Approver device
- Insider misuse with valid credentials

Operational controls remain mandatory.

---

# Extension Model

Extensions MUST:

- Use namespaced extension keys
- Preserve canonicalization rules
- Preserve signature integrity
- Undergo security review

Reserved namespace: extensions.harp.*

---

# Roadmap

Planned areas of future work:

- Streaming Extension (v0.3)
- Quorum approval model
- Post-quantum cryptography support
- Formal reference implementation
- Compliance automation toolkit
- Enterprise hardening profile

---

# Contribution

All proposals MUST include:

- Problem statement
- Threat analysis
- Backward compatibility analysis
- Compliance impact analysis
- Security review

Governance lifecycle is defined in HARP-GOVERNANCE.

---

# Disclaimer

HARP is a security protocol. Improper implementation may result in severe vulnerabilities.

Implementers MUST strictly follow normative requirements and pass compliance tests.

---

# License

Specification text may be released under an open documentation license (e.g., CC BY 4.0).  
Reference implementations may use appropriate open-source licenses.
