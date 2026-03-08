# HARP Gateway Specification (Draft v0.2)

**Status:** Draft (normative language; not yet ratified)  
**Date:** 2026-02-24  
**Scope:** Gateway semantics and HTTP transport binding for HARP exchanges (Artifact → Approval Request → Decision → Delivery).

## Contents

- `HARP_GATEWAY_RFC_Draft_v0_2.md` — Main gateway specification (normative).
- `HARP_GATEWAY_HTTP_BINDING_v0_2.md` — HTTP binding (REST + SSE + WebSocket) with mandatory Envelope framing.
- `schemas/` — JSON Schemas for gateway envelope bodies and resources.
- `test-vectors/` — Example request/response payloads and sequencing scenarios.
- `examples/` — Minimal illustrative examples and message flows.

## How to use this archive

1. Read `HARP_GATEWAY_RFC_Draft_v0_2.md` first (abstract semantics).
2. Then read `HARP_GATEWAY_HTTP_BINDING_v0_2.md` (wire protocol over HTTP).
3. Use `schemas/` for validation in implementations.
4. Use `test-vectors/` for conformance testing.

## Notes

- All HTTP/WS/SSE payloads are **Envelope-mandatory**.
- Push notifications are **out-of-band hints** and intentionally excluded from normative wire transport; clients MUST still use inbox APIs.
