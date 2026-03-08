# HARP-TRANSPORT: HTTP & WebSocket Binding Specification
Version: 0.2 Draft (Standards-Grade)
Status: Draft Specification (Transport Binding)

---

## Abstract

HARP-TRANSPORT defines normative transport bindings for HARP-CORE, HARP-PROMPT, and HARP-SESSION over HTTP and WebSocket.

This document specifies:

- Message serialization rules
- HTTP endpoint structure
- WebSocket session model
- Error mapping
- TLS and mTLS requirements
- Authentication layering
- Idempotency and retry semantics
- Size limits and fragmentation rules

HARP-TRANSPORT is OPTIONAL but RECOMMENDED for interoperable implementations.

---

## 1. Conventions

Normative language follows RFC 2119.

This document depends on:

- HARP-CORE v0.2
- HARP-PROMPT v0.2
- HARP-SESSION v0.2

---

## 2. Transport Principles

1. Transport MUST NOT modify canonicalized payloads.
2. Transport MUST preserve message integrity.
3. Transport MUST NOT alter JSON field ordering inside signed payloads.
4. Gateway MUST be treated as untrusted for plaintext.
5. TLS 1.2+ is REQUIRED. TLS 1.3 is RECOMMENDED.

---

## 3. Media Types

All HARP messages MUST use:

Content-Type: application/harp+json

Envelope-based transport MUST wrap payloads using the HARP-CORE Envelope schema.

**Note:** The HARP-GW HTTP Binding (see `HARP_GATEWAY_HTTP_BINDING_v0_2.md`) defines WebSocket control messages (e.g., `hello`) that are NOT Envelopes. These are bare JSON objects used for connection initialization. Additionally, the Gateway binding defines an extended endpoint set beyond the generic endpoints listed in §4.1 below (e.g., presence, pairing, withdraw, refresh).

---

## 4. HTTP Binding

### 4.1 Endpoints

Recommended endpoints:

POST /v1/artifact
POST /v1/decision
POST /v1/prompt
POST /v1/session/event

GET  /v1/session/{sessionId}
GET  /v1/status

### 4.2 Request Rules

- Requests MUST contain a valid HARP object or Envelope.
- Request body MUST be UTF-8 encoded JSON.
- Clients MUST include Idempotency-Key header for prompt.send and artifact.submit.

### 4.3 Response Codes

200 OK — accepted or processed  
202 Accepted — queued  
400 Bad Request — schema violation  
401 Unauthorized — authentication failure  
403 Forbidden — policy denial  
409 Conflict — idempotency violation  
422 Unprocessable Entity — hash mismatch  
500 Internal Server Error — server fault  

### 4.4 Idempotency

Servers MUST treat (requestId, hash) pairs as idempotent.

If duplicate detected:
- Return 200 or 202
- MUST NOT re-execute action

---

## 5. WebSocket Binding

### 5.1 Connection

Clients connect to:

wss://host/v1/ws

TLS is REQUIRED.

### 5.2 Framing

Each WebSocket frame MUST contain exactly one HARP Envelope object.

Binary frames MAY be used for encrypted payloads.
Text frames MUST contain UTF-8 JSON.

### 5.3 Keepalive

Implementations SHOULD send ping frames every 30 seconds.
Idle timeout SHOULD be configurable (RECOMMENDED 120 seconds).

### 5.4 Reconnection

Clients MUST support reconnect with exponential backoff.
Server MUST handle duplicate submissions safely.

---

## 6. TLS and mTLS Requirements

TLS 1.2 minimum.
TLS 1.3 preferred.

For enterprise deployments, mTLS MAY be REQUIRED.

If mTLS is used:
- Client certificates MUST be validated.
- Certificate thumbprints MAY be bound to deviceId.

---

## 7. Authentication Layering

Transport authentication is independent of HARP signatures.

Allowed methods:

- API Key
- OAuth2 Bearer Token
- JWT
- mTLS
- Basic Auth (discouraged for production)

Authentication MUST occur before payload processing.

---

## 8. Payload Size Limits

Implementations SHOULD enforce size limits.

RECOMMENDED maximum sizes:

- Artifact payload: 2 MB
- Prompt payload: 256 KB
- Snapshot payload: 5 MB

Servers MUST reject oversize payloads with 413 Payload Too Large.

---

## 9. Fragmentation

Transport-layer fragmentation is permitted (HTTP chunked encoding or WebSocket fragmentation).

Application-layer fragmentation is NOT defined in v0.2.

Streaming transport is out of scope.

---

## 10. Error Object Mapping

If using HTTP:

Errors MUST be returned as JSON body:

{
  "code": "HARP_ERR_SIGNATURE_INVALID",
  "message": "Signature verification failed",
  "retryable": false
}

HTTP status code MUST align with error semantics.

---

## 11. Security Considerations

- Always verify signature before execution.
- Do not trust TLS alone for authorization.
- Protect against request smuggling.
- Enforce rate limiting.
- Log metadata, not plaintext, unless configured.

---

## 12. Compliance

An implementation is HARP-TRANSPORT compliant if:

- TLS is enforced
- Media types are correct
- Envelope handling is correct
- Idempotency rules are enforced
- Error mapping follows specification

---

## Appendix A: Deployment Guidance (Non-Normative)

- Place Gateway behind WAF.
- Use HTTP/2 or HTTP/3 where available.
- Enable HSTS.
- Prefer JSON schema validation at ingress.

