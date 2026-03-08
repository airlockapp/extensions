/**
 * Named Pipe Proxy for secure gate script ↔ extension IPC.
 *
 * Architecture:
 *   Extension starts a named pipe server on activate().
 *   The gate script (hooksGateScript.js) connects via the pipe and sends an
 *   HTTP-like request envelope. The proxy:
 *     1. Validates the local secret (prevents other processes from injecting requests)
 *     2. Gets a fresh JWT from deviceAuth.ensureFreshToken()
 *     3. Forwards the request to the gateway with Bearer token
 *     4. On gateway 401: refreshes token and retries once
 *     5. Returns response to gate script
 *     6. On any auth failure: returns 503 → gate script fails OPEN
 *
 * Isolation: each extension instance uses enforcerId as part of the pipe name,
 * so multiple windows/instances of the same enforcer never collide.
 *
 * Fail modes (all fail OPEN per policy):
 *   - AIRLOCK_PIPE_NAME missing → gate uses no-auth code path → allow
 *   - AIRLOCK_LOCAL_SECRET missing → gate uses no-auth code path → allow
 *   - Proxy connection refused → gate allows (extension not running)
 *   - Proxy returns 503 → gate allows (extension not signed in / refresh failed)
 *
 * Fail CLOSED:
 *   - Proxy returns 401 → wrong local secret → gate blocks (security violation)
 *   - Proxy returns 403 → pairing_revoked → gate blocks
 */

import * as net from 'net';
import * as crypto from 'crypto';
import type { DeviceAuth } from './deviceAuth.js';
import { encryptPayload } from './crypto.js';

export interface ProxyOptions {
    enforcerId: string;
    gatewayUrl: string;
    localSecret: string;  // random per-session secret, written to wrapper script
    auth: () => DeviceAuth | undefined;  // lazy getter so extension.ts can reassign deviceAuth
    getEncryptionKey: () => Promise<string | null>;  // lazy getter for E2E encryption key from SecretStorage
    log: (msg: string) => void;
    onQuotaExceeded?: (errorCode: string) => void;  // called when gateway returns quota error (403 quota/429)
}

export class NamedPipeProxy {
    private _server: net.Server | null = null;
    private readonly _pipeName: string;

    constructor(private readonly _opts: ProxyOptions) {
        this._pipeName = NamedPipeProxy.getPipeName(_opts.enforcerId);
    }

    /** Returns the pipe name for a given enforcerId. */
    static getPipeName(enforcerId: string): string {
        // Windows: \\.\pipe\airlock-<id>
        // Unix:    /tmp/airlock-<id>.sock  (length ≤ 104 chars on macOS/Linux)
        if (process.platform === 'win32') {
            return `\\\\.\\pipe\\airlock-${enforcerId}`;
        }
        // Truncate enforcerId to stay within Unix socket path limit
        return `/tmp/airlock-${enforcerId.slice(0, 40)}.sock`;
    }

    /** Starts the named pipe server. Resolves when listening. */
    async start(): Promise<void> {
        // Remove stale Unix socket
        if (process.platform !== 'win32') {
            try {
                const { unlink } = await import('fs/promises');
                await unlink(this._pipeName);
            } catch { /* fine — file may not exist */ }
        }

        this._server = net.createServer((socket) => {
            this._handleConnection(socket);
        });

        await new Promise<void>((resolve, reject) => {
            this._server!.listen(this._pipeName, () => {
                this._opts.log(`✓ Named pipe proxy listening at ${this._pipeName}`);
                resolve();
            });
            this._server!.on('error', reject);
        });
    }

    /** Stops the server. */
    stop(): void {
        this._server?.close();
        this._server = null;
        this._opts.log('Named pipe proxy stopped');
    }

    // ── Connection handler ───────────────────────────────────────────────

    private _handleConnection(socket: net.Socket): void {
        let rawData = '';
        socket.setEncoding('utf8');
        this._opts.log('Named pipe: new connection received');

        socket.on('data', (chunk) => {
            rawData += chunk;
            // Simple framing: wait for \n\n (end of "headers") + content-length body
            if (rawData.includes('\n\n')) {
                this._processRequest(socket, rawData).catch((err) => {
                    this._opts.log(`Named pipe: request processing error: ${err}`);
                    this._sendError(socket, 500, 'internal_error');
                });
            }
        });

        socket.on('error', (err) => {
            this._opts.log(`Named pipe: socket error: ${err.message}`);
        });
    }

    private async _processRequest(socket: net.Socket, raw: string): Promise<void> {
        const [headerSection, ...bodyParts] = raw.split('\n\n');
        const body = bodyParts.join('\n\n');

        // Parse pseudo-HTTP headers: KEY: value
        const headers: Record<string, string> = {};
        for (const line of headerSection.split('\n')) {
            const idx = line.indexOf(': ');
            if (idx > 0) {
                headers[line.slice(0, idx).toLowerCase()] = line.slice(idx + 2).trim();
            }
        }

        const method = (headers['x-airlock-method'] || 'POST').toUpperCase();
        const path = headers['x-airlock-path'] || '/v1/artifacts';
        this._opts.log(`Named pipe: request ${method} ${path} (body=${body.length} bytes)`);

        // 1. Validate local secret (FAIL CLOSED — wrong secret = block)
        if (headers['x-airlock-secret'] !== this._opts.localSecret) {
            this._opts.log('⚠ Named pipe: wrong local secret — rejecting');
            this._sendError(socket, 401, 'wrong_secret');
            return;
        }

        // 2. Check if signed in (FAIL OPEN — not signed in = allow)
        const auth = this._opts.auth();
        this._opts.log(`Named pipe: auth present=${!!auth}, hasToken=${!!auth?.token}`);
        const token = await auth?.ensureFreshToken();
        if (!token) {
            this._opts.log('Named pipe: not signed in — returning 503 (gate will fail open)');
            this._sendError(socket, 503, 'not_authenticated');
            return;
        }
        this._opts.log(`Named pipe: auth token obtained (${token.slice(0, 10)}...)`);

        // 3. Encrypt plaintext payloads from hooks scripts (HARP-GW §2.1: zero-knowledge gateway)
        let forwardBody = body;
        if (method === 'POST' && path === '/v1/artifacts' && body) {
            try {
                const parsed = JSON.parse(body);
                if (parsed?.body?.ciphertext?.alg === 'none') {
                    const encKey = await this._opts.getEncryptionKey();
                    if (encKey) {
                        const plaintextData = parsed.body.ciphertext.data;
                        const encrypted = encryptPayload(plaintextData, encKey);
                        parsed.body.ciphertext = encrypted;
                        forwardBody = JSON.stringify(parsed);
                        this._opts.log('Named pipe: encrypted plaintext payload from hooks script');
                    } else {
                        this._opts.log('Named pipe: no encryption key — rejecting plaintext artifact (pair device first)');
                        this._sendError(socket, 403, 'encryption_key_missing');
                        return;
                    }
                }
            } catch (e) {
                this._opts.log(`Named pipe: body parse/encrypt error: ${e}`);
            }
        }

        // 4. Forward to gateway
        const gatewayUrl = `${this._opts.gatewayUrl}${path}`;
        this._opts.log(`Named pipe: forwarding to ${gatewayUrl}`);

        const response = await this._forwardToGateway(method, gatewayUrl, token, forwardBody);
        this._opts.log(`Named pipe: gateway responded ${response.status} (${response.body.length} bytes)`);

        // 5. On 401: refresh + retry once
        if (response.status === 401) {
            this._opts.log('Named pipe: got 401 from gateway, refreshing token...');
            const auth = this._opts.auth();
            const refreshed = auth ? await auth.refresh() : false;
            this._opts.log(`Named pipe: refresh result=${refreshed}`);
            if (refreshed && auth?.token) {
                const retry = await this._forwardToGateway(method, gatewayUrl, auth.token, forwardBody);
                this._opts.log(`Named pipe: retry responded ${retry.status}`);
                this._sendResponse(socket, retry.status, retry.body);
                return;
            }
            // Refresh failed — fail open
            this._opts.log('Named pipe: refresh failed — returning 503 (gate will fail open)');
            this._sendError(socket, 503, 'refresh_failed');
            return;
        }

        // 6. Detect quota responses and notify extension for status bar update
        if (response.status === 429 || response.status === 403) {
            try {
                const parsed = JSON.parse(response.body);
                const errorCode = parsed?.error || '';
                const quotaCodes = ['quota_exceeded', 'workspace_limit_reached', 'approver_limit_reached'];
                if (response.status === 429 || quotaCodes.includes(errorCode)) {
                    this._opts.onQuotaExceeded?.(errorCode || 'quota_exceeded');
                }
            } catch { /* body not JSON — ignore */ }
        }

        this._sendResponse(socket, response.status, response.body);
    }

    private async _forwardToGateway(
        method: string,
        url: string,
        token: string,
        body: string
    ): Promise<{ status: number; body: string }> {
        try {
            this._opts.log(`Named pipe: fetch ${method} ${url}`);
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
                this._opts.log(`Named pipe: gateway error ${resp.status}: ${text.substring(0, 200)}`);
            }
            return { status: resp.status, body: text };
        } catch (err) {
            this._opts.log(`Named pipe: gateway fetch error: ${err}`);
            return { status: 503, body: '{"error":"gateway_unreachable"}' };
        }
    }

    // ── Response helpers ─────────────────────────────────────────────────

    private _sendResponse(socket: net.Socket, status: number, body: string): void {
        const response = `STATUS: ${status}\n\n${body}`;
        socket.write(response, 'utf8', () => socket.end());
    }

    private _sendError(socket: net.Socket, status: number, code: string): void {
        this._sendResponse(socket, status, JSON.stringify({ error: code }));
    }

    // ── Static helpers ───────────────────────────────────────────────────

    /** Generates a cryptographically random local secret. */
    static generateLocalSecret(): string {
        return crypto.randomBytes(32).toString('hex');
    }
}
