# HARP-GOVERNANCE: Governance, Versioning & Registry Model
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Governance & Evolution)

---

## Abstract

HARP-GOVERNANCE defines the formal governance structure, versioning model, registry system, and extension lifecycle rules for the Human Authorization & Review Protocol (HARP) suite.

This document specifies:

- Specification versioning rules
- Backward and forward compatibility requirements
- Registry management (artifact types, error codes, algorithms, extensions)
- Change control process
- Deprecation policy
- Extension proposal process
- Reference implementation policy
- Compliance evolution rules

This document ensures that HARP evolves predictably, securely, and without fragmentation.

---

# 1. Versioning Model

HARP specifications use Semantic Versioning:

MAJOR.MINOR.PATCH

## 1.1 MAJOR

Incremented when:

- Backward compatibility is broken
- Canonicalization rules change
- Signature format changes
- Hash algorithm requirements change

Implementations MUST reject unsupported MAJOR versions.

## 1.2 MINOR

Incremented when:

- New optional fields are added
- New artifact types are added
- New error codes are added
- New algorithms are registered

Backward compatibility MUST be preserved.

## 1.3 PATCH

Incremented when:

- Editorial clarifications are made
- Non-normative improvements are added
- Typographical corrections are made

PATCH changes MUST NOT affect interoperability.

---

# 2. Compatibility Rules

## 2.1 Backward Compatibility

A MINOR version update MUST:

- Not remove required fields
- Not change canonicalization rules
- Not change required algorithms

## 2.2 Forward Compatibility

Implementations SHOULD:

- Ignore unknown optional fields
- Ignore unknown extension namespaces
- Reject unknown required enum values

---

# 3. Registry System

HARP defines the following registries.

## 3.1 Artifact Type Registry

Maintains valid artifactType values.

Initial entries:

- plan.review
- task.review
- patch.review
- command.review
- checkpoint.review
- prompt.send
- session.start
- session.status
- session.snapshot
- session.end

New entries require governance approval.

---

## 3.2 Error Code Registry

Maintains standardized error codes.

Core entries include:

- HARP_ERR_CANONICALIZATION
- HARP_ERR_HASH_MISMATCH
- HARP_ERR_SIGNATURE_INVALID
- HARP_ERR_EXPIRED
- HARP_ERR_REPLAY
- HARP_ERR_SCOPE
- HARP_ERR_POLICY_DENY
- HARP_ERR_TRANSPORT
- HARP_ERR_UNSUPPORTED

Extensions may register prefixed codes:

HARP_PROMPT_ERR_*
HARP_SESSION_ERR_*

---

## 3.3 Algorithm Registry

Defines allowed cryptographic algorithms.

Initial allowed algorithms:

Signatures:
- Ed25519

Hash:
- SHA-256

Key Exchange (optional):
- X25519

Future algorithms MUST be registered before normative use.

---

## 3.4 Extension Namespace Registry

Extensions MUST use namespaced keys:

extensions.<vendor>.<feature>

Vendor namespaces MUST be globally unique.

Reserved namespace:

extensions.harp.*

---

## 3.5 Metadata Key Registry

Maintains well-known metadata keys used in gateway envelope `body.metadata` for routing and display purposes (see HARP-GW §6.4).

Initial entries:

| Key | Classification |
|---|---|
| `routingToken` | Routing |
| `approverId` | Routing |
| `tenantId` | Routing |
| `workspaceName` | Display |
| `repoName` | Display |

Implementations MAY define additional keys. New well-known keys require governance approval.

---

## 3.6 Message Type Registry

Maintains valid `msgType` values used in HARP Envelopes and WebSocket control messages.

Initial entries:

| msgType | Direction | Defined in |
|---|---|---|
| `artifact.submit` | Client → Gateway | HARP-GW HTTP Binding |
| `artifact.accepted` | Gateway → Client | HARP-GW HTTP Binding |
| `decision.submit` | Client → Gateway | HARP-GW HTTP Binding |
| `decision.accepted` | Gateway → Client | HARP-GW HTTP Binding |
| `decision.deliver` | Gateway → Client | HARP-GW HTTP Binding |
| `approval.request` | Gateway → Client | HARP-GW HTTP Binding |
| `ack.submit` | Client → Gateway | HARP-GW HTTP Binding |
| `ack.accepted` | Gateway → Client | HARP-GW HTTP Binding |
| `inbox.page` | Gateway → Client | HARP-GW HTTP Binding |
| `exchange.status` | Gateway → Client | HARP-GW HTTP Binding |
| `exchange.withdrawn` | Gateway → Client | HARP-GW HTTP Binding |
| `refresh.request` | Gateway → Client | HARP-GW HTTP Binding |
| `hello` | Client → Gateway | HARP-GW HTTP Binding (WS control) |
| `error` | Gateway → Client | HARP-GW HTTP Binding |

New message types require governance approval.

---

# 4. Change Control Process

## 4.1 Proposal Lifecycle

Changes follow:

1. Draft proposal
2. Public review period
3. Security review
4. Revision
5. Approval
6. Version increment
7. Publication

Security-impacting changes MUST undergo formal review.

---

## 4.2 Deprecation Policy

When deprecating:

- Mark feature as deprecated in MINOR release
- Provide migration guidance
- Remove only in next MAJOR version

Deprecated features MUST remain interoperable until MAJOR bump.

---

# 5. Reference Implementations

At least one open reference implementation SHOULD exist for:

- HARP-CORE
- HARP-KEYMGMT
- HARP-TRANSPORT

Reference implementation SHOULD:

- Pass official compliance tests
- Publish supported version
- Be security-reviewed

---

# 6. Interoperability Working Model

To prevent fragmentation:

- Implementations MUST publish supported version
- Implementations MUST publish supported algorithms
- Implementations SHOULD test cross-vendor compatibility
- Changes MUST maintain canonicalization determinism

---

# 7. Version Negotiation (Transport-Level)

When using HARP-TRANSPORT:

Clients SHOULD send:

X-HARP-Version: 0.2

Servers SHOULD respond with:

X-HARP-Version: 0.2

If unsupported version:

- Server MUST return 426 Upgrade Required
- Response MUST include supported version range

---

# 8. Extension Proposal Requirements

To register a new extension:

Submission MUST include:

- Problem statement
- Threat analysis
- Canonicalization impact assessment
- Hash/signature impact assessment
- Backward compatibility analysis
- Compliance test additions

Extensions MUST NOT:

- Modify canonicalization rules
- Weaken signature requirements
- Remove mandatory replay protections

---

# 9. Security Governance Requirements

All normative cryptographic changes MUST:

- Include updated threat model
- Include updated compliance tests
- Include migration plan
- Include interoperability validation

---

# 10. Specification Publication Requirements

Each release MUST publish:

- Updated RFC draft
- Updated JSON schemas
- Updated test vectors
- Updated compliance test requirements
- Change log

---

# 11. Governance Structure (Suggested Model)

HARP MAY adopt:

- Steering committee
- Security review board
- Registry maintainer role
- Community contribution process

Governance MUST prioritize:

- Security stability
- Backward compatibility
- Deterministic behavior
- Vendor neutrality

---

# 12. Compliance with Governance

An implementation is governance-compliant if:

- It declares supported version
- It follows versioning rules
- It does not introduce undocumented changes
- It respects registry definitions
- It adheres to deprecation policy

---

# 13. Security Considerations

Improper governance can:

- Fragment ecosystem
- Break interoperability
- Introduce silent security regressions

Strict change control is REQUIRED for security-sensitive protocol components.

