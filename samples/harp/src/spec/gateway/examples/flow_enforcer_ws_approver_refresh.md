# Example Flow: Enforcer WS wait + Approver manual refresh

## Actors
- Enforcer: `enf-01`
- Approver: `app-01`
- RequestId: `req-u6s2nku4oo`

## Steps

1. Enforcer submits Artifact via `POST /v1/artifacts` (or WS)  
   - Payload: `test-vectors/01_artifact_submit.json`

2. Gateway persists Exchange (state: PendingApproval) and emits Approval Request  
   - WS to Approver (if connected) OR SSE event `approval.request`  
   - Also persists in Approver Inbox.
   - Payload example: `test-vectors/02_approval_request_sse_or_ws.json`

3. Approver receives push hint OR user refreshes manually.  
   - Approver calls `GET /v1/approvers/{approverId}/inbox` and picks `req-u6s2nku4oo`

4. Approver submits Decision via `POST /v1/decisions`  
   - Payload: `test-vectors/03_decision_submit.json`

5. Gateway marks Exchange Decided and delivers to Enforcer’s bound channel  
   - WS (preferred) or SSE (optional)  
   - Payload: `test-vectors/04_decision_deliver_ws_or_sse.json`

6. Enforcer acknowledges delivery  
   - `POST /v1/acks`  
   - Payload: `test-vectors/05_ack_submit.json`
