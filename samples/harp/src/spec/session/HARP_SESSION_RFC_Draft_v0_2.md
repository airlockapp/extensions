# HARP-SESSION: Human Authorization & Review Protocol (Session Extension)
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Extension)

---

## Abstract

HARP-SESSION defines lifecycle management and snapshot semantics for AI Agent sessions operating under HARP enforcement. It standardizes session identifiers, lifecycle events, snapshot integrity protection, ordering semantics, and compliance rules. Live streaming is explicitly excluded in v0.2.

---

## 1. Scope and Dependencies

HARP-SESSION is OPTIONAL and depends on HARP-CORE canonicalization and hashing rules.

This extension standardizes:

- session.start
- session.status
- session.snapshot
- session.end

Streaming semantics are reserved for future revisions.

---

## 2. Session Model

### 2.1 Session Identifier

`sessionId` MUST be globally unique (UUID or ULID RECOMMENDED).

A session represents a bounded unit of AI Agent activity.

### 2.2 Lifecycle Events

Events MUST include `eventType`:

- session.start
- session.status
- session.snapshot
- session.end

---

## 3. session.start

Required fields:
- sessionId
- eventType = session.start
- createdAt
- agentHost

Optional:
- repoRef
- metadata

HE SHOULD emit session.start at the beginning of interaction.

---

## 4. session.status

Represents high-level state transitions.

Allowed states:
- idle
- planning
- editing
- executing
- waiting_approval
- error

Implementations MAY emit session.status multiple times.
Ordering SHOULD follow creation time.

---

## 5. session.snapshot

### 5.1 Purpose

Snapshots provide point-in-time non-streaming representations of session state.

### 5.2 SnapshotSignable

`snapshotHash` MUST be computed over canonical JSON of snapshot object excluding `snapshotHash`.

`snapshotHashAlg` MUST be "SHA-256".

### 5.3 Integrity

HE MUST verify snapshotHash before forwarding or storing snapshots.

### 5.4 Idempotency

The tuple (sessionId, snapshotId, snapshotHash) MUST be treated as idempotent.

Duplicate submissions MUST NOT create duplicate records.

---

## 6. session.end

Required:
- sessionId
- eventType = session.end
- endedAt
- reason (user_end | timeout | policy_kill)

After session.end, further events with same sessionId SHOULD be rejected.

---

## 7. Ordering and Consistency

HARP-SESSION does not guarantee global ordering.

Within a sessionId:
- Events SHOULD be processed in createdAt order.
- Implementations MUST handle out-of-order delivery gracefully.
- Idempotency rules MUST be enforced.

---

## 8. Error Handling

Use HARP-CORE error codes.

Additional recommended codes:
- HARP_SESSION_ERR_INVALID_STATE
- HARP_SESSION_ERR_DUPLICATE_SNAPSHOT
- HARP_SESSION_ERR_SESSION_CLOSED

---

## 9. Security Considerations

- Snapshots MAY contain sensitive data.
- Gateway MUST remain zero-knowledge.
- Integrity is guaranteed by snapshotHash.
- Replay risk mitigated via idempotency rules.
- Streaming is intentionally excluded to reduce complexity and attack surface.

---

## 10. Test Vectors (Normative)

See HARP_SESSION_Test_Vectors_v0_2.md.
