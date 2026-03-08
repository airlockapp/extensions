# HARP Gateway HTTP Binding (REST + SSE + WebSocket) — Draft v0.2

**Status:** Draft  
**Date:** 2026-03-02  
**Applies to:** HARP-GW v0.2

This document defines the HTTP wire protocol binding for the HARP Gateway. It is **Envelope-mandatory**: every message body sent to, or emitted by, the Gateway MUST be a HARP Envelope.

## 1. Media Type and Encoding

- `Content-Type: application/harp+json`
- UTF-8 encoded JSON.
- All timestamps MUST be RFC3339.
- All IDs MUST be case-sensitive strings unless otherwise specified.

## 2. Envelope (wire requirement)

All HTTP request bodies, SSE `data:` payloads, and WebSocket messages MUST be:
- an **Envelope** object
- with `msgType` set per message types below

**Exception:** WebSocket control messages (e.g., `hello` per §5.1) are NOT Envelopes. They are bare JSON objects with a `msgType` field but without the full Envelope structure (`requestId`, `createdAt`, `sender`, `body`). Implementations MUST distinguish control messages from Envelope messages by inspecting the `msgType` value.

See `schemas/harp-gateway-envelope.schema.json` for the wire schema of the envelope + gateway-required fields.

## 3. REST Endpoints

### 3.1 Submit Artifact (Enforcer → Gateway)
`POST /v1/artifacts`

**Request body (Envelope):**
- `msgType`: `artifact.submit`
- `requestId`: REQUIRED
- `sender.enforcerId`: REQUIRED
- `body`: MUST conform to `schemas/harp-gateway-artifact-submit.schema.json`

**Responses:**
- `202 Accepted` with an Envelope `artifact.accepted`
- `409 Conflict` for AlreadyExistsConflict
- `400 Bad Request` for validation errors
- `422 Unprocessable Entity` for semantic failures (e.g., no approver available, artifact already expired)

### 3.2 Submit Decision (Approver → Gateway)
`POST /v1/decisions`

**Request body (Envelope):**
- `msgType`: `decision.submit`
- `requestId`: REQUIRED
- `sender.approverId`: REQUIRED
- `body`: MUST conform to `schemas/harp-gateway-decision-submit.schema.json`

**Responses:**
- `200 OK` with Envelope `decision.accepted`
- `409 Conflict` for AlreadyDecidedConflict
- `400 Bad Request` for validation errors
- `404 Not Found` if exchange does not exist

### 3.3 List Approver Inbox (active items)
`GET /v1/approvers/{approverId}/inbox?cursor=&limit=`

**Response body (Envelope):**
- `msgType`: `inbox.page`
- `body`: MUST conform to `schemas/harp-gateway-inbox-page.schema.json`

Returns only items with status `Pending`. Items that have been decided, expired, or withdrawn MUST NOT appear.

### 3.4 List Expired Inbox
`GET /v1/approvers/{approverId}/inbox/expired`

**Response body (Envelope):**
- `msgType`: `inbox.page`
- `body`: Same schema as §3.3

Returns inbox items that have expired (status `Expired`). This endpoint supports Approver UX for showing historical/expired requests.

### 3.5 Delete Inbox Item
`DELETE /v1/approvers/{approverId}/inbox/{requestId}`

Removes a specific inbox item from the Approver's inbox. Used for cleanup of dismissed items.

**Responses:**
- `204 No Content` on success
- `404 Not Found` if the inbox item does not exist

### 3.6 Exchange Status
`GET /v1/exchanges/{requestId}`

**Response body (Envelope):**
- `msgType`: `exchange.status`
- `body`: MUST conform to `schemas/harp-gateway-exchange-status.schema.json`

**Responses:**
- `200 OK` with exchange details
- `404 Not Found` if exchange does not exist

### 3.7 Enforcer Wait (long-poll fallback)
`GET /v1/exchanges/{requestId}/wait?timeout=30`

- `timeout` is seconds (1..60 RECOMMENDED).
- If a decision is available within timeout, returns `200 OK` with `decision.deliver` envelope.
- Otherwise returns `204 No Content`.

### 3.8 Exchange Withdraw
`POST /v1/exchanges/{requestId}/withdraw`

Allows the Enforcer to withdraw a pending approval request (e.g., when the user took manual action and no mobile approval is needed).

**Responses:**
- `200 OK` with Envelope `exchange.withdrawn`
- `404 Not Found` if exchange does not exist
- `409 Conflict` if exchange is already in a terminal state (Decided, Expired, Withdrawn)

**Side effects:**
- Exchange state transitions to **Withdrawn**
- All related Approver inbox items MUST be marked as withdrawn
- The Gateway SHOULD invalidate any cached inbox state for affected Approvers

### 3.9 Refresh Request
`POST /v1/requests/{requestId}/refresh?enforcerDeviceId={id}`

Requests the Enforcer to reissue an expired or pending artifact. The Gateway forwards a `refresh.request` control message to the Enforcer via its active real-time channel.

**Responses:**
- `200 OK` with `{ "status": "forwarded" }` if the control message was delivered
- `400 Bad Request` if `enforcerDeviceId` is missing
- `503 Service Unavailable` if the Enforcer is offline or its channel is unavailable

### 3.10 Presence Query
`GET /v1/presence/enforcers?tenantId={tenantId}`

Returns the current presence status of all enforcers within the tenant scope. See HARP-GW §6.5.

**Response body:**
```json
[
  {
    "enforcerDeviceId": "enf-01",
    "status": "online",
    "lastSeenAt": "2026-03-02T14:00:00Z",
    "transport": "websocket",
    "workspaceName": "airlock",
    "enforcerLabel": "Antigravity",
    "capabilities": { "push": true }
  }
]
```

**Responses:**
- `200 OK` with array of presence records
- `400 Bad Request` if `tenantId` query parameter is missing

### 3.11 Single Enforcer Presence
`GET /v1/presence/enforcers/{enforcerDeviceId}`

Returns the presence record for a specific enforcer.

**Responses:**
- `200 OK` with presence record object
- `404 Not Found` if the enforcer is not found in the presence store

### 3.12 Pairing Lifecycle

Pairing endpoints establish trust relationships between Enforcers and Approvers (see HARP-GW §6.6).

#### 3.12.1 Initiate Pairing
`POST /v1/pairing/initiate`

Creates a new pairing session with a short-lived pairing code.

**Request body:**
- `enforcerId`: REQUIRED
- `enforcerLabel`: OPTIONAL
- `workspaceName`: OPTIONAL
- `publicKey`: RECOMMENDED (for E2E encryption key exchange)

**Responses:**
- `200 OK` with pairing session details (code, nonce, expiresAt)

#### 3.12.2 Resolve Pairing Code
`GET /v1/pairing/resolve/{code}`

Resolves a pairing code to retrieve session details. Used by the Approver to discover the Enforcer's identity.

**Responses:**
- `200 OK` with session details (nonce, enforcerLabel, publicKey)
- `404 Not Found` if code is invalid or expired

#### 3.12.3 Pairing Status
`GET /v1/pairing/{nonce}/status`

Polls the current state of a pairing session. Used by the Enforcer to detect when the Approver has completed their side.

**Responses:**
- `200 OK` with session state and completion details
- `404 Not Found` if session not found

#### 3.12.4 Complete Pairing
`POST /v1/pairing/complete`

Completes the pairing handshake. The Approver confirms the pairing, establishing the routing token.

**Request body:**
- `nonce`: REQUIRED
- `approverId`: REQUIRED
- `publicKey`: RECOMMENDED

**Responses:**
- `200 OK` with routing token and enforcer metadata
- `404 Not Found` if session not found or expired
- `409 Conflict` if session already completed

## 4. SSE Endpoints

### 4.1 Approver SSE stream
`GET /v1/sse/approvers/{approverId}`

The server emits events where `data:` is an Envelope.

**Event types (SSE `event:` field):**
- `approval.request` — Envelope msgType `approval.request`
- `ping` — keepalive (OPTIONAL; data MAY be empty)

At minimum, the Gateway MUST ensure all pending approval requests are retrievable via the inbox listing API, regardless of SSE connectivity.

### 4.2 Enforcer SSE stream (OPTIONAL)
`GET /v1/sse/enforcers/{enforcerId}`

Events:
- `decision.deliver` — Envelope msgType `decision.deliver`

## 5. WebSocket Endpoint

`GET /v1/ws?role={enforcer|approver}&id={enforcerId|approverId}`

All WS frames MUST be JSON Envelopes.

### 5.1 Hello Message

Upon WebSocket connection, the client SHOULD send a `hello` message as the first frame:

```json
{
  "msgType": "hello",
  "capabilities": { "push": true, "poll": false, "sse": false },
  "workspaceName": "airlock",
  "enforcerLabel": "Antigravity"
}
```

The Gateway SHOULD use the hello message to:
- Initialize the presence record for the connected enforcerId (see HARP-GW §6.5)
- Record capabilities for delivery strategy selection
- Store display metadata (`workspaceName`, `enforcerLabel`) for Approver UX

If no hello is received within a reasonable timeout (RECOMMENDED: 5 seconds), the Gateway SHOULD default to basic presence tracking using the WebSocket connection lifecycle (connect = online, disconnect = offline).

### 5.2 Gateway-emitted msgTypes
- `approval.request`
- `decision.deliver`
- `refresh.request` — control message requesting artifact reissue (see §3.9)
- `error`

### 5.3 Client-emitted msgTypes
- `hello` — connection identification and capabilities (see §5.1)
- `artifact.submit` (OPTIONAL if REST is used for submit)
- `decision.submit` (OPTIONAL if REST is used for submit)
- `ack.submit`

## 6. Ack Endpoint / Message Ack

### 6.1 REST Ack
`POST /v1/acks`

**Request body (Envelope):**
- `msgType`: `ack.submit`
- `body`: MUST conform to `schemas/harp-gateway-ack-submit.schema.json`

**Response:**
- `200 OK` with `ack.accepted`

## 7. Deterministic routing rule (default)

When multiple active channels exist for the same Enforcer identity, the Gateway MUST deliver `decision.deliver` to the **most recent active channel**. If no channel is active, the decision MUST be retained for inbox/poll retrieval until expiration/retention.

## 8. HTTP Response Codes

The following HTTP status codes are used across Gateway endpoints:

| Code | Meaning | Usage |
|---|---|---|
| `200 OK` | Request processed successfully | Decision accepted, presence query, pairing |
| `202 Accepted` | Request queued for processing | Artifact accepted |
| `204 No Content` | Success with no body | Inbox item deleted, long-poll timeout |
| `400 Bad Request` | Schema or parameter validation error | Missing required fields |
| `401 Unauthorized` | Authentication failure | Invalid or missing credentials |
| `403 Forbidden` | Authorization failure | Insufficient permissions |
| `404 Not Found` | Resource does not exist | Exchange, inbox item, enforcer, pairing session |
| `409 Conflict` | Idempotency or state conflict | Duplicate artifact with different hash, already decided |
| `422 Unprocessable Entity` | Semantic validation failure | No approver available, artifact already expired |
| `500 Internal Server Error` | Server fault | Unexpected errors |
| `503 Service Unavailable` | Dependency unavailable | Enforcer offline for refresh requests |

## 9. Minimal error envelope

On error, the Gateway MUST return an Envelope:
- `msgType`: `error`
- `body`: conforming to `schemas/harp-gateway-error.schema.json`

## 10. Platform Endpoints (Non-HARP)

The Gateway MAY proxy requests to a platform backend for operational concerns outside the HARP protocol scope (e.g., device registration, authentication, tenant management). Such endpoints are implementation-specific and not governed by this specification.
