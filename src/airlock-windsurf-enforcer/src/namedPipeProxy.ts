/**
 * Named Pipe Proxy — Trusted Security Boundary (v3 Architecture)
 *
 * This is the core security runtime for Airlock hook enforcement.
 * All decision logic lives here — the bootstrap script in .windsurf/
 * is transport-only and contains zero secrets.
 *
 * Architecture (v3 §2):
 *   Bootstrap (transport) → Named Pipe → THIS MODULE (security boundary)
 *     → Gateway → Approver → Allow / Deny
 *
 * Responsibilities:
 *   1. Receive JSON hook requests from bootstrap via named pipe
 *   2. Validate protocol version (v3.1 §5)
 *   3. Enforce payload size limits (v3.1 §6)
 *   4. Self-protection: block access to Airlock files
 *   5. Auto-approve pattern matching
 *   6. Build HARP artifact envelope
 *   7. Encrypt payloads (zero-knowledge gateway)
 *   8. Submit to gateway and poll for decision
 *   9. Apply fail mode policy (failClosed/failOpen)
 *   10. Return allow/deny decision to bootstrap
 *
 * Security:
 *   - Unix socket: chmod 0600 after creation (v3.1 §2.1)
 *   - Pipe collision handling (v3.1 §3.1)
 *   - Per-workspace pipe isolation via workspace hash (v3 §5-6)
 */

import * as net from 'net';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { DeviceAuth } from './deviceAuth.js';
import { encryptPayload, type EncryptedPayload } from './crypto.js';
import { evaluateDndForAction } from './dndClient.js';

// ── Constants ────────────────────────────────────────────────────────────────
const SUPPORTED_PROTOCOL_VERSION = 1;
const MAX_PAYLOAD_BYTES = 1 * 1024 * 1024; // 1 MB (v3.1 §6)
const POLL_INTERVAL_SEC = 25;

// Protected Airlock files — self-protection (moved from gate script)
const PROTECTED_FILES = [
    "hooks.json", "airlock-bootstrap.cmd", "airlock-bootstrap.sh",
    "airlock-bootstrap.js", "airlock-gate.cmd", "airlock-gate.sh",
    "hooksGateScript.js", "airlock-hooks.log",
];

// ── Types ────────────────────────────────────────────────────────────────────

/** JSON request from bootstrap (v3 §12) */
interface HookRequest {
    kind: "hook_request";
    protocolVersion: number;
    workspaceHash: string;
    cwdFolderName?: string;
    payload: Record<string, unknown>;
}

/** JSON response to bootstrap (v3 §12) */
interface HookResponse {
    permission: "allow" | "deny";
    message?: string;
    agentMessage?: string;
}

export interface ProxyOptions {
    enforcerId: string;
    gatewayUrl: string;
    workspaceName: string;
    repoName: string;
    failMode: "failClosed" | "failOpen";
    autoApprovePatterns: string[];
    auth: () => DeviceAuth | undefined;
    getEncryptionKey: () => Promise<string | null>;
    getRoutingToken: () => string | null;
    timeoutSeconds: number;
    log: (msg: string) => void;
    logDiag?: (msg: string) => void;
    onQuotaExceeded?: (errorCode: string) => void;
    isAutoModeEnabled?: () => boolean;
}

export class NamedPipeProxy {
    private _server: net.Server | null = null;
    private readonly _pipeName: string;
    private _opts: ProxyOptions;

    constructor(opts: ProxyOptions, pipeName: string) {
        this._opts = opts;
        this._pipeName = pipeName;
    }

    /** Update options at runtime (e.g., when config changes). */
    updateOptions(updates: Partial<ProxyOptions>): void {
        this._opts = { ...this._opts, ...updates };
    }

    get pipeName(): string { return this._pipeName; }

    // ── Workspace hash (v3 §5) ──────────────────────────────────────────────

    /** Compute deterministic workspace hash per v3 §5. */
    static computeWorkspaceHash(workspacePath: string): string {
        let normalized = path.resolve(workspacePath);
        if (process.platform === 'win32') {
            normalized = normalized.toLowerCase();
        }
        const digest = crypto.createHash('sha256').update(normalized).digest('hex');
        return digest.substring(0, 16);
    }

    /** Returns the pipe name for a given workspace hash (v3 §6). */
    static getPipeName(workspaceHash: string): string {
        if (process.platform === 'win32') {
            // Use a Windsurf-specific suffix so multiple enforcers (Cursor, Copilot, etc.)
            // can coexist in the same workspace without pipe name collisions.
            return `\\\\.\\pipe\\airlock-ws-windsurf-${workspaceHash}`;
        }
        return `/tmp/airlock-ws-windsurf-${workspaceHash}.sock`;
    }

    // ── Server lifecycle (v3 §7) ────────────────────────────────────────────

    /** Starts the named pipe server. Resolves when listening. */
    async start(): Promise<void> {
        // Collision handling on Unix (v3.1 §3.1)
        if (process.platform !== 'win32') {
            await this._handleSocketCollision();
        }

        this._server = net.createServer((socket) => {
            this._handleConnection(socket);
        });

        await new Promise<void>((resolve, reject) => {
            this._server!.listen(this._pipeName, () => {
                this._opts.log(`✓ Pipe server listening at ${this._pipeName}`);
                resolve();
            });
            this._server!.on('error', reject);
        });

        // Unix socket permissions: chmod 0600 (v3.1 §2.1)
        if (process.platform !== 'win32') {
            try {
                fs.chmodSync(this._pipeName, 0o600);
                this._opts.log('✓ Socket permissions set to 0600 (owner only)');
            } catch (err) {
                this._opts.log(`⚠ Failed to set socket permissions: ${err}`);
            }
        }
    }

    /** Stops the server and cleans up socket file. */
    stop(): void {
        this._server?.close();
        this._server = null;
        // Cleanup Unix socket file (v3 §7)
        if (process.platform !== 'win32') {
            try { fs.unlinkSync(this._pipeName); } catch { /* fine */ }
        }
        this._opts.log('Pipe server stopped');
    }

    // ── Collision handling (v3.1 §3.1) ──────────────────────────────────────

    private async _handleSocketCollision(): Promise<void> {
        // Check if socket file exists
        try {
            fs.accessSync(this._pipeName);
        } catch {
            return; // No existing socket — nothing to handle
        }

        this._opts.log('Existing socket found — testing if active...');

        // Try connecting to see if another runtime is active
        const isActive = await new Promise<boolean>((resolve) => {
            const testSocket = net.createConnection(this._pipeName, () => {
                testSocket.destroy();
                resolve(true);
            });
            testSocket.on('error', () => resolve(false));
            testSocket.setTimeout(300, () => {
                testSocket.destroy();
                resolve(false);
            });
        });

        if (isActive) {
            this._opts.log('⚠ Active runtime detected on existing socket — reusing');
            // Don't delete — there's a live server
            throw new Error('Another Airlock runtime is already active for this workspace');
        }

        // Stale socket — safe to delete
        try {
            fs.unlinkSync(this._pipeName);
            this._opts.log('Deleted stale socket file');
        } catch { /* fine */ }
    }

    // ── Connection handler ──────────────────────────────────────────────────

    private _handleConnection(socket: net.Socket): void {
        let rawData = '';
        let totalBytes = 0;
        socket.setEncoding('utf8');

        socket.on('data', (chunk: string) => {
            totalBytes += Buffer.byteLength(chunk, 'utf8');

            // Payload size limit (v3.1 §6)
            if (totalBytes > MAX_PAYLOAD_BYTES) {
                this._opts.log(`⚠ Payload exceeds ${MAX_PAYLOAD_BYTES} bytes — rejecting`);
                this._sendResponse(socket, { permission: 'deny', message: 'Payload too large' });
                return;
            }

            rawData += chunk;
            // JSON is newline-delimited
            const nlIdx = rawData.indexOf('\n');
            if (nlIdx >= 0) {
                const jsonStr = rawData.substring(0, nlIdx);
                this._processRequest(socket, jsonStr).catch((err) => {
                    this._opts.log(`Request processing error: ${err}`);
                    this._sendResponse(socket, { permission: 'deny', message: 'Internal error' });
                });
            }
        });

        socket.on('error', (err) => {
            this._opts.log(`Socket error: ${err.message}`);
        });
    }

    // ── Request processing (v3 §13) ─────────────────────────────────────────

    private async _processRequest(socket: net.Socket, raw: string): Promise<void> {
        // 1. Parse JSON request
        let request: HookRequest;
        try {
            request = JSON.parse(raw);
        } catch {
            this._sendResponse(socket, { permission: 'deny', message: 'Invalid JSON request' });
            return;
        }

        // 2. Validate request structure
        if (request.kind !== 'hook_request') {
            this._sendResponse(socket, { permission: 'deny', message: 'Unknown request kind' });
            return;
        }

        // 3. Protocol version validation (v3.1 §5)
        if (request.protocolVersion !== SUPPORTED_PROTOCOL_VERSION) {
            this._opts.log(`⚠ Protocol version mismatch: got ${request.protocolVersion}, expected ${SUPPORTED_PROTOCOL_VERSION}`);
            this._sendResponse(socket, { permission: 'deny', message: 'Incompatible protocol version' });
            return;
        }

        const payload = request.payload || {};

        // Log raw payload keys for diagnostics
        this._opts.logDiag?.(`Hook request: protocolVersion=${request.protocolVersion} wsHash=${request.workspaceHash} cwdFolder=${request.cwdFolderName || '(none)'} payloadKeys=[${Object.keys(payload).join(',')}]`);

        // Repo name comes from extension config (workspace name or folder name)
        const effectiveRepoName = this._opts.repoName;
        this._opts.logDiag?.(`  repoName=${effectiveRepoName}`);

        // 4. Normalize Windsurf payload fields
        const normalizedPayload = this._normalizePayload(payload);
        const event = normalizedPayload.event as string || 'unknown';
        const commandLine = (normalizedPayload.command || normalizedPayload.toolName || '') as string;
        const filePath = ((normalizedPayload.filePath || normalizedPayload.file_path || normalizedPayload.path || '') as string)
            .replace(/\\/g, '/').toLowerCase();

        this._opts.log(`Event: ${event} | Action: ${commandLine || filePath || '?'}`);

        // 4a. Auto-mode check — if OFF, allow immediately (enforcer is not gating)
        if (this._opts.isAutoModeEnabled && !this._opts.isAutoModeEnabled()) {
            this._opts.log(`Auto-mode OFF — allowing "${commandLine || event}" without gateway approval`);
            this._sendResponse(socket, { permission: 'allow' });
            return;
        }

        // 5. Self-protection: block tampering with Airlock files
        const cmdLower = commandLine.toLowerCase();
        const toolInputStr = (typeof normalizedPayload.input === 'string'
            ? normalizedPayload.input
            : JSON.stringify(normalizedPayload.input || '')).toLowerCase();

        if (PROTECTED_FILES.some(p => {
            const pLower = p.toLowerCase();
            return filePath.includes(pLower) || cmdLower.includes(pLower) || toolInputStr.includes(pLower);
        })) {
            this._sendResponse(socket, {
                permission: 'deny',
                message: 'Access to protected Airlock files is blocked',
                agentMessage: 'You cannot modify Airlock configuration files (hooks.json, airlock-bootstrap.*, etc). These files are protected.',
            });
            return;
        }

        // 6. Auto-approve pattern matching
        if (commandLine && this._isAutoApproved(commandLine)) {
            this._opts.logDiag?.(`AUTO-APPROVED: "${commandLine}" matches auto-approve pattern`);
            this._sendResponse(socket, { permission: 'allow' });
            return;
        }

        // 7. Check if signed in (fail mode applies)
        const auth = this._opts.auth();
        const token = await auth?.ensureFreshToken();
        if (!token) {
            this._opts.log('Not signed in — applying fail mode');
            this._applyFailMode(socket, 'User not signed in');
            return;
        }

        // 8. Check routing token (pairing)
        const routingToken = this._opts.getRoutingToken();
        if (!routingToken) {
            this._opts.log('Not paired — applying fail mode');
            this._applyFailMode(socket, 'Workspace not paired');
            return;
        }

        // 9. Build HARP artifact envelope
        const requestId = `req-${crypto.randomUUID()}`;
        const msgId = `msg-${crypto.randomUUID()}`;
        const actionType = event === 'pre_run_command' ? 'terminal_command' : 'agent_step';

        // 9a. Evaluate DND policies before building & submitting artifact.
        if (commandLine) {
            try {
                const dndMatch = await evaluateDndForAction(
                    {
                        endpointUrl: this._opts.gatewayUrl,
                        workspaceId: this._opts.workspaceName,
                        enforcerId: this._opts.enforcerId,
                        authToken: token,
                    },
                    {
                        actionType,
                        commandText: commandLine,
                    }
                );

                if (dndMatch) {
                    const isApprove = dndMatch.decision === 'approve';

                    // Minimal, non-sensitive log so users can see when DND applied.
                    this._opts.log(
                        `DND: ${dndMatch.scope} policy (${dndMatch.policyMode}) → ${dndMatch.decision.toUpperCase()}`
                    );

                    // Fire-and-forget audit artifact so mobile can see bypassed commands.
                    this._submitDndAuditArtifact(
                        token,
                        routingToken,
                        actionType,
                        commandLine,
                        effectiveRepoName,
                        event,
                        dndMatch.decision
                    ).catch(() => { /* non-fatal */ });

                    const message = isApprove
                        ? 'Action auto-approved by DND policy.'
                        : 'Action auto-denied by DND policy.';

                    this._sendResponse(socket, {
                        permission: isApprove ? 'allow' : 'deny',
                        message,
                        agentMessage: !isApprove
                            ? 'This action was automatically denied by a DND policy you configured in the Airlock mobile app.'
                            : undefined,
                    });
                    return;
                } else {
                    this._opts.logDiag?.('DND: no matching policy for this action');
                }
            } catch {
                // On any DND evaluation error, fall back to normal approval flow
            }
        }

        const plaintextContent = JSON.stringify({
            actionType,
            commandText: commandLine,
            buttonText: this._buildDescription(normalizedPayload),
            workspace: this._opts.workspaceName,
            repoName: effectiveRepoName,
            source: 'windsurf-hooks',
            hookEvent: event,
            toolInput: normalizedPayload.input
                ? JSON.stringify(normalizedPayload.input).substring(0, 500)
                : undefined,
        });

        // 10. Encrypt payload (zero-knowledge gateway)
        let ciphertext: EncryptedPayload | { alg: string; data: string } = { alg: 'none', data: plaintextContent };
        const encKey = await this._opts.getEncryptionKey();
        if (encKey) {
            try {
                ciphertext = encryptPayload(plaintextContent, encKey);
                this._opts.logDiag?.('Encrypted payload for zero-knowledge gateway');
            } catch (e) {
                this._opts.log(`Encryption error: ${e}`);
            }
        } else {
            this._opts.log('No encryption key — pair device first');
            this._sendResponse(socket, {
                permission: 'deny',
                message: 'Encryption key missing — pair your device first',
            });
            return;
        }

        const envelope = {
            msgId,
            msgType: 'artifact.submit',
            requestId,
            createdAt: new Date().toISOString(),
            sender: { enforcerId: this._opts.enforcerId },
            body: {
                artifactType: 'command-approval',
                artifactHash: crypto.createHash('sha256')
                    .update(`${actionType}:${commandLine}:${Date.now()}`)
                    .digest('hex'),
                ciphertext,
                expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
                metadata: {
                    repoName: effectiveRepoName,
                    workspaceName: this._opts.workspaceName,
                    routingToken,
                },
            },
        };

        // 11. Submit to gateway
        this._opts.logDiag?.(`Submitting artifact (requestId=${requestId})`);
        const submitResult = await this._forwardToGateway(
            'POST', '/v1/artifacts', token, JSON.stringify(envelope)
        );

        // Handle submit response
        if (submitResult.status === 503) {
            this._opts.log('Gateway unreachable — applying fail mode');
            this._applyFailMode(socket, 'Gateway unreachable');
            return;
        }
        if (submitResult.status === 429 || submitResult.status === 403) {
            const errorCode = this._parseErrorCode(submitResult.body);
            const quotaCodes = ['quota_exceeded', 'workspace_limit_reached', 'approver_limit_reached'];
            if (submitResult.status === 429 || quotaCodes.includes(errorCode)) {
                this._opts.onQuotaExceeded?.(errorCode || 'quota_exceeded');
                this._applyFailMode(socket, `Quota exceeded (${errorCode})`);
                return;
            }
            // Non-quota 403 = security error (e.g., pairing revoked) — always deny
            this._sendResponse(socket, {
                permission: 'deny',
                message: `Access denied: ${errorCode || 'pairing revoked'}`,
            });
            return;
        }
        if (submitResult.status === 401) {
            // Try refresh + retry once
            this._opts.log('Gateway 401 — refreshing token...');
            const refreshed = auth ? await auth.refresh() : false;
            if (refreshed && auth?.token) {
                const retry = await this._forwardToGateway(
                    'POST', '/v1/artifacts', auth.token, JSON.stringify(envelope)
                );
                if (retry.status < 200 || retry.status >= 300) {
                    this._applyFailMode(socket, 'Gateway auth failed after refresh');
                    return;
                }
            } else {
                this._applyFailMode(socket, 'Token refresh failed');
                return;
            }
        }
        if (submitResult.status < 200 || submitResult.status >= 300) {
            this._sendResponse(socket, {
                permission: 'deny',
                message: `Gateway error: ${submitResult.status}`,
            });
            return;
        }

        this._opts.logDiag?.(`Artifact accepted (${submitResult.status}). Polling for decision...`);

        // 12. Poll for decision
        const decision = await this._pollForDecision(requestId, token);
        this._sendResponse(socket, decision);
    }

    // ── Decision polling ────────────────────────────────────────────────────

    private async _pollForDecision(requestId: string, token: string): Promise<HookResponse> {
        const deadline = Date.now() + this._opts.timeoutSeconds * 1000;
        let pollCount = 0;

        while (Date.now() < deadline) {
            pollCount++;
            const remainingSec = Math.ceil((deadline - Date.now()) / 1000);
            const serverTimeout = Math.min(POLL_INTERVAL_SEC, remainingSec);
            if (serverTimeout <= 0) { break; }

            const waitPath = `/v1/exchanges/${requestId}/wait?timeout=${serverTimeout}`;
            this._opts.logDiag?.(`Poll ${pollCount}: waiting up to ${serverTimeout}s...`);

            try {
                const auth = this._opts.auth();
                const freshToken = await auth?.ensureFreshToken() || token;
                const result = await this._forwardToGateway('GET', waitPath, freshToken, '');

                if (result.status === 204 || !result.body) {
                    this._opts.logDiag?.(`Poll ${pollCount}: no decision yet`);
                    continue;
                }

                if (result.status >= 200 && result.status < 300) {
                    try {
                        const outer = JSON.parse(result.body);
                        const inner = outer.body || outer;
                        const decision = (inner.decision || inner.Decision || inner.status || '').toLowerCase();

                        this._opts.logDiag?.(`Poll ${pollCount}: decision="${decision}"`);

                        if (decision === 'approve' || decision === 'approved') {
                            this._opts.log('[OK] APPROVED');
                            return { permission: 'allow' };
                        }

                        if (decision === 'reject' || decision === 'rejected') {
                            return {
                                permission: 'deny',
                                message: 'Action REJECTED by Airlock mobile approver.',
                                agentMessage: 'STOP. This action was explicitly REJECTED by the human approver via the Airlock mobile app. ' +
                                    'You MUST NOT retry this command, rephrase it, or attempt any equivalent action. ' +
                                    'Inform the user and wait for their explicit new instruction.',
                            };
                        }

                        this._opts.logDiag?.(`Poll ${pollCount}: unexpected decision="${decision}"`);
                    } catch { /* body parse error — retry */ }
                }
            } catch (err) {
                this._opts.logDiag?.(`Poll ${pollCount} error: ${err}. Retrying...`);
                await new Promise(r => setTimeout(r, 1000));
            }
        }

        // Timeout — explicit rejection, never overridden by failOpen (INV-8)
        return {
            permission: 'deny',
            message: 'Approval timed out',
            agentMessage: 'Airlock approval timed out. The action was blocked. Do not retry automatically.',
        };
    }

    // ── Gateway communication ───────────────────────────────────────────────

    private async _forwardToGateway(
        method: string,
        gatewayPath: string,
        token: string,
        body: string
    ): Promise<{ status: number; body: string }> {
        const url = `${this._opts.gatewayUrl}${gatewayPath}`;
        try {
            this._opts.logDiag?.(`Gateway: ${method} ${url}`);
            const resp = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/harp+json',
                    'Authorization': `Bearer ${token}`,
                },
                body: method !== 'GET' ? body : undefined,
            });
            const text = await resp.text();
            if (resp.status !== 200 && resp.status !== 204) {
                this._opts.log(`Gateway error ${resp.status}: ${text.substring(0, 200)}`);
            }
            return { status: resp.status, body: text };
        } catch (err) {
            this._opts.log(`Gateway fetch error: ${err}`);
            return { status: 503, body: '{"error":"gateway_unreachable"}' };
        }
    }

    /**
     * Submit a short-lived audit artifact for DND-bypassed commands so they are
     * visible in the mobile app's history without blocking execution.
     */
    private async _submitDndAuditArtifact(
        token: string,
        routingToken: string,
        actionType: string,
        commandLine: string,
        effectiveRepoName: string,
        event: string,
        decision: "approve" | "reject"
    ): Promise<void> {
        try {
            const encKey = await this._opts.getEncryptionKey();
            if (!encKey) {
                return;
            }

            const plaintextContent = JSON.stringify({
                actionType,
                commandText: commandLine,
                buttonText: `DND ${decision === "approve" ? "APPROVE" : "DENY"} audit`,
                workspace: this._opts.workspaceName,
                repoName: effectiveRepoName,
                source: 'windsurf-hooks-dnd',
                hookEvent: event,
                dndDecision: decision,
            });

            const ciphertext = encryptPayload(plaintextContent, encKey);
            const auditRequestId = `audit-${crypto.randomUUID()}`;
            const msgId = `msg-${crypto.randomUUID()}`;

            // Let gateway clamp/expire; request a short TTL (~1 minute).
            const expiresAt = new Date(Date.now() + 60_000).toISOString();

            const envelope = {
                msgId,
                msgType: 'artifact.submit',
                requestId: auditRequestId,
                createdAt: new Date().toISOString(),
                sender: { enforcerId: this._opts.enforcerId },
                body: {
                    artifactType: 'command-approval',
                    artifactHash: crypto.createHash('sha256')
                        .update(`dnd-audit:${actionType}:${commandLine}:${Date.now()}`)
                        .digest('hex'),
                    ciphertext,
                    expiresAt,
                    metadata: {
                        repoName: effectiveRepoName,
                        workspaceName: this._opts.workspaceName,
                        routingToken,
                        dndAudit: 'true',
                        dndDecision: decision,
                    },
                },
            };

            await this._forwardToGateway(
                'POST',
                '/v1/artifacts',
                token,
                JSON.stringify(envelope)
            );
        } catch {
            // Audit failures are non-fatal and must not affect command outcome.
        }
    }

    // ── Payload normalization (Windsurf-specific) ───────────────────────────

    private _normalizePayload(payload: Record<string, unknown>): Record<string, unknown> {
        const p = { ...payload };

        // 1. Use agent_action_name as the event (Windsurf's native field)
        //    pre_run_command:  { agent_action_name: "pre_run_command",  tool_info: { command_line, cwd } }
        //    pre_mcp_tool_use: { agent_action_name: "pre_mcp_tool_use", tool_info: { mcp_server_name, mcp_tool_name, mcp_tool_arguments } }
        //    pre_read_code:    { agent_action_name: "pre_read_code",    tool_info: { file_path } }
        //    pre_write_code:   { agent_action_name: "pre_write_code",   tool_info: { file_path, edits } }
        if (!p.event && p.agent_action_name) {
            p.event = p.agent_action_name;
        }
        if (!p.event && p.hook_event_name) {
            p.event = p.hook_event_name;
        }

        // 2. Flatten Windsurf's tool_info object into top-level fields
        //    This is the key Windsurf-specific transformation.
        if (p.tool_info && typeof p.tool_info === 'object') {
            const ti = p.tool_info as Record<string, unknown>;
            if (ti.command_line !== undefined && !p.command) { p.command = ti.command_line; }
            if (ti.cwd !== undefined && !p.cwd) { p.cwd = ti.cwd; }
            if (ti.mcp_server_name !== undefined && !p.serverName) { p.serverName = ti.mcp_server_name; }
            if (ti.mcp_tool_name !== undefined && !p.toolName) { p.toolName = ti.mcp_tool_name; }
            if (ti.mcp_tool_arguments !== undefined && !p.input) { p.input = ti.mcp_tool_arguments; }
            if (ti.file_path !== undefined && !p.filePath) { p.filePath = ti.file_path; }
            if (ti.edits !== undefined) { p.edits = ti.edits; }
        }

        // 3. Normalize additional Windsurf-style field names (legacy/alternative shapes)
        if (!p.toolName && p.tool_name) { p.toolName = p.tool_name; }
        if (!p.input && p.tool_input) {
            if (typeof p.tool_input === 'string') {
                try { p.input = JSON.parse(p.tool_input as string); } catch { p.input = p.tool_input; }
            } else {
                p.input = p.tool_input;
            }
        }
        if (!p.filePath && p.file_path) { p.filePath = p.file_path; }

        // 4. Infer event from payload shape if still not present
        if (!p.event) {
            if (p.command !== undefined && p.cwd !== undefined) { p.event = 'pre_run_command'; }
            else if (p.serverName !== undefined || (p.toolName && !p.command)) { p.event = 'pre_mcp_tool_use'; }
            else if (p.filePath !== undefined && !p.edits) { p.event = 'pre_read_code'; }
            else if (p.filePath !== undefined && p.edits !== undefined) { p.event = 'pre_write_code'; }
            else { p.event = 'unknown'; }
        }

        return p;
    }

    // ── Description builder (Windsurf-specific) ─────────────────────────────

    private _buildDescription(payload: Record<string, unknown>): string {
        const fp = (payload.filePath || payload.file_path || payload.path || '(unknown)') as string;
        switch ((payload.event || 'unknown') as string) {
            case 'pre_run_command':
                return `Terminal command: ${payload.command || '(unknown)'}${payload.cwd ? ' (cwd: ' + payload.cwd + ')' : ''}`;
            case 'pre_mcp_tool_use':
                return `MCP: ${payload.serverName ? payload.serverName + '/' : ''}${payload.toolName || '(unknown)'}`;
            case 'pre_read_code':
                return `Read file: ${fp}`;
            case 'pre_write_code': {
                const editCount = Array.isArray(payload.edits) ? (payload.edits as unknown[]).length : 0;
                return `Write file: ${fp}${editCount > 0 ? ' (' + editCount + ' edit' + (editCount > 1 ? 's' : '') + ')' : ''}`;
            }
            case 'pre_user_prompt':
                return `User prompt: ${((payload.prompt || '') as string).substring(0, 200) || '(prompt)'}`;
            default:
                return `Hook event: ${payload.event || 'unknown'}: ${payload.command || payload.toolName || fp || '?'}`;
        }
    }

    // ── Auto-approve matching (moved from gate script) ───────────────────────

    private _isAutoApproved(commandText: string): boolean {
        const patterns = this._opts.autoApprovePatterns;
        if (!patterns || patterns.length === 0) { return false; }

        const lower = commandText.toLowerCase();
        for (const pattern of patterns) {
            const p = pattern.trim();
            if (!p) { continue; }
            try {
                if (p.startsWith('/') && p.lastIndexOf('/') > 0) {
                    const last = p.lastIndexOf('/');
                    const re = new RegExp(p.substring(1, last), p.substring(last + 1) || 'i');
                    if (re.test(commandText)) { return true; }
                } else if (lower.includes(p.toLowerCase())) {
                    return true;
                }
            } catch {
                if (lower.includes(p.toLowerCase())) { return true; }
            }
        }
        return false;
    }

    // ── Fail mode (v3 §14-15) ───────────────────────────────────────────────

    private _applyFailMode(socket: net.Socket, reason: string): void {
        if (this._opts.failMode === 'failOpen') {
            this._opts.log(`${reason} — allowing (failOpen)`);
            this._sendResponse(socket, { permission: 'allow' });
        } else {
            this._opts.log(`${reason} — denying (failClosed)`);
            this._sendResponse(socket, { permission: 'deny', message: reason });
        }
    }

    // ── Response helpers ────────────────────────────────────────────────────

    private _sendResponse(socket: net.Socket, response: HookResponse): void {
        const json = JSON.stringify(response);
        socket.write(json, 'utf8', () => socket.end());
    }

    // ── Utility ─────────────────────────────────────────────────────────────

    private _parseErrorCode(body: string): string {
        try {
            const parsed = JSON.parse(body);
            return parsed?.error || '';
        } catch {
            return '';
        }
    }

    /** Generates a cryptographically random local secret. */
    static generateLocalSecret(): string {
        return crypto.randomBytes(32).toString('hex');
    }
}
