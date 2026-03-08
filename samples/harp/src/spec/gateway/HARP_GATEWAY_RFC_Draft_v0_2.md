# HARP Gateway Specification (HARP-GW) — Draft v0.2

**Status:** Draft  
**Date:** 2026-02-24  
**Normative Language:** The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

## 1. Purpose and Scope

This document defines the **HARP Gateway (GW)**: an intermediary service that provides **store-and-forward**, **correlated routing**, and **delivery** for HARP exchanges between:

- **Enforcer (HE):** submits an Artifact and awaits a Decision.
- **Approver (MA):** receives Approval Requests and submits Decisions.
- **Gateway (GW):** brokers the exchange and routes Decisions back to the correct Enforcer.

This specification defines **abstract gateway semantics** (independent of transport). An HTTP binding (REST + SSE + WebSocket) is defined in `HARP_GATEWAY_HTTP_BINDING_v0_2.md`.

## 2. Design Principles

### 2.1 Zero-knowledge relay
The Gateway SHALL be treated as **untrusted** and **zero-knowledge**: it MUST NOT require access to plaintext artifact contents. The Gateway MUST operate using ciphertext payloads and minimal metadata required for routing and lifecycle management.

### 2.2 Correlation-first model
The Gateway MUST correlate all exchange activities using a stable **requestId**.

### 2.3 Durable exchange
The Gateway MUST provide a durable Exchange record for each requestId, supporting disconnected clients (Approver or Enforcer).

### 2.4 Envelope-mandatory framing
All gateway-facing and gateway-emitted messages MUST be framed as a **HARP Envelope**. (See HTTP binding for wire representation.)

## 3. Core Concepts

### 3.1 Exchange
An **Exchange** is a correlated interaction identified by `requestId` that relates:
- an **Artifact submission** (from Enforcer),
- one or more **Approval Requests** (to Approver(s)),
- a **Decision submission** (from an Approver),
- **Decision delivery** (to the Enforcer).

#### 3.1.1 Exchange Identity
- `requestId` (string): REQUIRED. Unique within the scope of the Gateway’s retention window.
- `tenantId` (string/UUID): OPTIONAL/RECOMMENDED if multi-tenant.
- `createdAt` (RFC3339 datetime): REQUIRED.
- `expiresAt` (RFC3339 datetime): REQUIRED.

#### 3.1.2 Exchange Immutability
Once an Exchange enters state **Decided**, the decision outcome for that requestId MUST be immutable.

### 3.2 Messages
The Gateway uses messages (enveloped) in two directions:

- **Upstream submissions:** Artifact, Decision, Ack
- **Downstream deliveries:** Approval Request, Decision Delivery, Error

Each message MUST include:
- `msgId` (string, unique): REQUIRED for gateway-emitted messages; RECOMMENDED for submitted messages.
- `requestId`: REQUIRED (correlation)
- `createdAt`: REQUIRED
- `expiresAt`: REQUIRED or derivable from Exchange

### 3.3 Inboxes
The Gateway MUST provide at least one durable inbox mechanism:
- **Approver Inbox:** lists pending Approval Requests.
- **Enforcer Inbox:** lists pending Decision Deliveries (if Enforcer was offline).

Inbox items MUST be retrievable until they are acknowledged, expire, or exceed retention policy.

## 4. State Machine

### 4.1 States
An Exchange MUST be in exactly one of the following states:

- **PendingApproval**: Artifact accepted; awaiting Decision.
- **Decided**: Decision accepted; awaiting delivery/ack (optional).
- **Delivered**: Decision delivered and acknowledged by Enforcer (optional but RECOMMENDED).
- **Expired**: Exchange expired without an accepted decision.
- **Withdrawn**: Exchange withdrawn by Enforcer before a Decision was submitted (OPTIONAL).
- **Cancelled**: Exchange cancelled by policy or administrative action (OPTIONAL).

### 4.2 Transitions (normative)
- Artifact accepted ⇒ state becomes **PendingApproval**.
- Decision accepted ⇒ state becomes **Decided**.
- Decision delivered and acknowledged ⇒ state MAY become **Delivered**.
- Time > `expiresAt` and state is not **Decided** ⇒ state MUST become **Expired**.
- If **Withdrawn** is implemented, Enforcer requests withdrawal while in **PendingApproval** ⇒ state becomes **Withdrawn**. Withdrawn MUST prevent accepting new Decisions and MUST remove related items from Approver Inboxes.
- If **Cancelled** is implemented, cancellation MUST prevent accepting new decisions.

## 5. Idempotency and Conflict Rules

### 5.1 Artifact submission idempotency
The Gateway MUST treat an Artifact submission as idempotent under the key:

- `(requestId, artifactHash)`

Rules:
- If an identical `(requestId, artifactHash)` is resubmitted, the Gateway MUST NOT create duplicate approval requests and MUST return a success response.
- If `requestId` is reused with a different `artifactHash`, the Gateway MUST reject with a conflict error (AlreadyExistsConflict).

### 5.2 Decision submission idempotency
The Gateway MUST treat a Decision submission as idempotent under at least one of:
- `(requestId, signerKeyId, nonce)` (RECOMMENDED), or
- `(requestId, decisionHash)`

Rules:
- Duplicate decisions under the idempotency key MUST be accepted as no-ops.
- If an Exchange is already **Decided** and a different Decision is submitted, the Gateway MUST reject with a conflict error (AlreadyDecidedConflict).

## 6. Routing Semantics

### 6.1 Enforcer delivery address
When accepting an Artifact for `requestId`, the Gateway MUST bind the Exchange to an **Enforcer Delivery Address**, derived from:
- the authenticated Enforcer identity (enforcerId), and
- the current active connection/channel (if any).

If multiple active channels exist for the same enforcerId, the Gateway MUST define deterministic selection. The HTTP binding defines a default rule: “most recent active channel”.

### 6.2 Approver selection
The Gateway MUST support delivery of Approval Requests to one or more eligible Approvers.

Approver selection MAY be:
- explicitly addressed (recipient approverId in the message),
- tenant-wide (any approver with the right entitlement), or
- policy-based (e.g., role-based, rotation).

The selection algorithm is out of scope; the observable requirements are:
- Approval Requests MUST be persisted to Approver Inbox(es).
- Approval Requests MUST be deliverable over real-time channels when available.

### 6.3 Metadata Forwarding Policy

When the Gateway constructs an Approval Request from an Artifact submission, `body.metadata` from the submitted envelope MAY contain fields used for both **routing** and **display** purposes. The Gateway MUST apply a forwarding policy:

- **Routing-only fields** (e.g., `routingToken`, `approverId`, `tenantId`) MUST NOT be forwarded into the Approval Request envelope delivered to the Approver. These fields are consumed by the Gateway for routing decisions and MUST be stripped.
- **Display-safe fields** (e.g., `workspaceName`, `repoName`) SHOULD be forwarded into the Approval Request body so that the Approver application can present contextual information to the human reviewer.
- If no display-safe fields are present, the Gateway MAY omit `metadata` from the Approval Request body entirely.

> **Rationale:** Per HARP-CORE Appendix A, `repoRef` SHOULD be kept opaque to avoid leaking repository URLs to the Gateway. Display-safe metadata uses human-friendly labels (e.g., `"airlock"`) rather than full paths or URLs, preserving this guidance while enabling useful presentation in Approver applications.

### 6.4 Well-Known Metadata Keys

The following metadata keys are defined for interoperability. Implementations MAY define additional keys.

| Key | Classification | Description |
|---|---|---|
| `routingToken` | Routing | Opaque token for zero-knowledge approver selection. MUST NOT be forwarded. |
| `approverId` | Routing | Explicit approver address (backward-compatible fallback). MUST NOT be forwarded. |
| `tenantId` | Routing | Tenant scope for multi-tenant deployments. MUST NOT be forwarded. |
| `workspaceName` | Display | Human-friendly workspace/project label (e.g., `"airlock"`). SHOULD be forwarded. |
| `repoName` | Display | Human-friendly repository identifier. SHOULD be forwarded. |

### 6.5 Enforcer Presence

The Gateway MAY track the **presence** (connectivity status) of connected Enforcers to provide operational visibility to Approver applications.

#### 6.5.1 Presence States

- **Online**: At least one active real-time channel (WebSocket or SSE) exists for the enforcerId.
- **Offline**: No active channel; last activity exceeds the presence TTL.

#### 6.5.2 Presence Records

Presence records MAY include:

| Field | Requirement | Description |
|---|---|---|
| `enforcerDeviceId` | REQUIRED | Unique identifier for the enforcer instance |
| `status` | REQUIRED | `online` or `offline` |
| `lastSeenAt` | RECOMMENDED | RFC3339 timestamp of last activity |
| `transport` | OPTIONAL | `websocket`, `sse`, or `poll` |
| `workspaceName` | OPTIONAL | Human-friendly workspace/project label |
| `enforcerLabel` | OPTIONAL | Human-friendly enforcer type label |
| `capabilities` | OPTIONAL | Object describing enforcer capabilities |

#### 6.5.3 Presence Semantics

- Presence is **best-effort** and informational. It MUST NOT affect routing correctness — Decisions MUST be deliverable regardless of presence status (via inbox/poll fallback per §7.1).
- Presence records SHOULD expire automatically after a configurable TTL (RECOMMENDED: 10 minutes) if no keepalive or messages are received.
- The Gateway SHOULD update presence on WebSocket connect/disconnect and on receipt of keepalive messages.

### 6.6 Pairing

The Gateway SHOULD support a **pairing** mechanism that establishes a trust relationship between an Enforcer and an Approver. Pairing enables:

- Opaque routing token generation (for zero-knowledge approver selection per §2.1)
- Enforcer identity metadata exchange (enforcerLabel, workspace context)
- Key exchange for end-to-end encryption

The pairing lifecycle consists of:

1. **Initiation**: One party generates a short-lived pairing code.
2. **Resolution**: The other party resolves the code to obtain session details.
3. **Completion**: Both parties confirm, establishing the routing token and shared context.

Pairing sessions MUST be short-lived (RECOMMENDED: 10 minutes) and single-use.

## 7. Delivery Guarantees and Acknowledgements

### 7.1 Delivery guarantee
- Approval Requests: **at-least-once** delivery to Approver(s).
- Decision Deliveries: **at-least-once** delivery to Enforcer.

### 7.2 Acknowledgement
The Gateway MUST support acknowledgement of gateway-emitted messages using an Ack mechanism.

An Ack MUST include:
- `msgId`
- `requestId`
- `status` in { `received`, `processed` }
- `ackAt` (RFC3339 datetime)

Upon valid Ack, the Gateway MUST stop redelivering the acknowledged message.

### 7.3 Redelivery policy
If an inbox item is not acknowledged, the Gateway MAY redeliver it over SSE/WS and MUST continue to expose it via inbox listing until expiry/retention.

## 8. Error Model (abstract)

The Gateway MUST produce structured errors that include:
- `code` (string)
- `message` (string)
- `requestId` (if applicable)
- `details` (object, optional)

Conflict errors MUST be distinguishable from validation errors.

## 9. Security Considerations (normative)

- The Gateway MUST authenticate Enforcers and Approvers.
- The Gateway MUST authorize operations per tenant and role/entitlement.
- The Gateway MUST NOT require plaintext to route; it SHALL handle ciphertext and minimal metadata.
- Decisions MUST be delivered without modification; the Enforcer remains responsible for signature verification.

## 10. Conformance

An implementation conforms to HARP-GW v0.2 if it implements:
- Exchange lifecycle and state machine (Section 4)
- Idempotency/conflict rules (Section 5)
- Routing semantics and durable inboxes (Sections 3.3 and 6)
- At-least-once delivery + Ack mechanism (Section 7)
- Envelope-mandatory message framing (Section 2.4)

Transport conformance is defined in `HARP_GATEWAY_HTTP_BINDING_v0_2.md`.
