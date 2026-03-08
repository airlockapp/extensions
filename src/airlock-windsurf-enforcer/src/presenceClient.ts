import * as vscode from "vscode";
import WebSocket from "ws";

export type PresenceEvent = "connected" | "disconnected" | "error" | "refreshRequest" | "pairing.revoked";

export interface RefreshRequestMessage {
    requestId: string;
    createdAt: string;
}

/**
 * Persistent WebSocket client for Enforcer presence tracking.
 * Connects to the Gateway, sends capabilities hello, handles ping/pong,
 * and listens for control messages (refresh.request).
 * Auto-reconnects with exponential backoff.
 */
export class PresenceClient {
    private ws: WebSocket | null = null;
    private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    private reconnectDelay = 1000; // Start at 1s
    private readonly maxReconnectDelay = 30000; // Max 30s
    private disposed = false;
    private _isConnected = false;

    private readonly emitter = new vscode.EventEmitter<PresenceEvent>();
    public readonly onEvent = this.emitter.event;

    private readonly refreshEmitter = new vscode.EventEmitter<RefreshRequestMessage>();
    public readonly onRefreshRequest = this.refreshEmitter.event;

    constructor(
        private readonly out: vscode.OutputChannel,
        private readonly enforcerVersion: string,
        private readonly enforcerLabel: string = "Windsurf"
    ) { }

    get isConnected(): boolean {
        return this._isConnected;
    }

    /**
     * Connect to the Gateway WebSocket endpoint for presence.
     * Uses Bearer token for authentication instead of client credentials.
     */
    connect(gatewayUrl: string, tokenGetter: () => string | undefined, enforcerDeviceId: string): void {
        if (this.ws) {
            this.disconnect();
        }

        // Build WS URL
        const wsBase = gatewayUrl.replace(/^http/, "ws");
        const params = new URLSearchParams({
            role: "enforcer",
            id: enforcerDeviceId,
        });

        // Get fresh token for this connection attempt
        const token = tokenGetter();

        // Pass token as query param for WS (headers not universally supported)
        if (token) {
            params.set("token", token);
        }

        const wsUrl = `${wsBase}/v1/ws?${params.toString()}`;
        this.out.appendLine(`[Airlock Presence] Connecting to ${wsBase}/v1/ws...`);

        try {
            // rejectUnauthorized respects the allowSelfSignedCerts setting (via NODE_TLS_REJECT_UNAUTHORIZED)
            const rejectUnauthorized = process.env["NODE_TLS_REJECT_UNAUTHORIZED"] !== "0";
            const wsOptions: WebSocket.ClientOptions = {
                headers: token ? { Authorization: `Bearer ${token}` } : undefined,
                rejectUnauthorized,
            };
            this.ws = new WebSocket(wsUrl, wsOptions);
        } catch (err) {
            this.out.appendLine(`[Airlock Presence] Failed to create WebSocket: ${err}`);
            this.scheduleReconnect(gatewayUrl, tokenGetter, enforcerDeviceId);
            return;
        }

        this.ws.on("open", () => {
            this._isConnected = true;
            this.reconnectDelay = 1000; // Reset backoff
            this.out.appendLine("[Airlock Presence] Connected ✓");
            this.emitter.fire("connected");

            // Send capabilities hello
            this.sendHello();
        });

        this.ws.on("message", (data: WebSocket.Data) => {
            try {
                const text = data.toString();
                const msg = JSON.parse(text);

                if (msg.msgType === "ping") {
                    // Respond to application-level pings
                    this.ws?.send(JSON.stringify({ msgType: "pong" }));
                } else if (msg.msgType === "refresh.request") {
                    this.out.appendLine(`[Airlock Presence] Refresh request for: ${msg.requestId}`);
                    this.refreshEmitter.fire({
                        requestId: msg.requestId,
                        createdAt: msg.createdAt,
                    });
                } else if (msg.msgType === "pairing.revoked") {
                    // Mobile approver has removed this pairing — clear token and go offline
                    this.out.appendLine(`[Airlock Presence] Pairing revoked by mobile approver: ${msg.reason ?? ""}`);
                    this.emitter.fire("pairing.revoked");
                    // Do not reconnect after revocation — stay offline
                    this.dispose();
                }
            } catch {
                // Non-JSON message, ignore
            }
        });

        this.ws.on("close", (code: number, reason: Buffer) => {
            this._isConnected = false;
            this.out.appendLine(`[Airlock Presence] Disconnected (code=${code})`);
            this.emitter.fire("disconnected");

            if (!this.disposed) {
                this.scheduleReconnect(gatewayUrl, tokenGetter, enforcerDeviceId);
            }
        });

        this.ws.on("error", (err: Error) => {
            this.out.appendLine(`[Airlock Presence] Error: ${err.message}`);
            this.emitter.fire("error");
        });

        // Handle WebSocket-level pong (auto-handled by ws library)
        this.ws.on("pong", () => {
            // Connection is alive
        });
    }

    /**
     * Send capabilities hello message on connect, including workspace info.
     */
    private sendHello(): void {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            return;
        }

        const ws = vscode.workspace.workspaceFolders?.[0];
        const workspaceName = ws?.name || "unknown";

        const hello = JSON.stringify({
            msgType: "hello",
            capabilities: {
                harpVersion: "1.0",
                enforcerVersion: this.enforcerVersion,
                supportsRefresh: "true",
            },
            workspaceName,
            enforcerLabel: this.enforcerLabel,
        });

        this.ws.send(hello);
        this.out.appendLine(`[Airlock Presence] Sent capabilities hello (workspace=${workspaceName})`);
    }

    /**
     * Schedule reconnection with exponential backoff.
     */
    private scheduleReconnect(
        gatewayUrl: string,
        tokenGetter: () => string | undefined,
        enforcerDeviceId: string
    ): void {
        if (this.disposed || this.reconnectTimer) {
            return;
        }

        this.out.appendLine(
            `[Airlock Presence] Reconnecting in ${this.reconnectDelay / 1000}s...`
        );

        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.connect(gatewayUrl, tokenGetter, enforcerDeviceId);
        }, this.reconnectDelay);

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (max)
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    }

    /**
     * Disconnect from the Gateway.
     */
    disconnect(): void {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }

        if (this.ws) {
            this.ws.removeAllListeners();
            if (this.ws.readyState === WebSocket.OPEN) {
                this.ws.close(1000, "Extension deactivating");
            }
            this.ws = null;
        }

        this._isConnected = false;
    }

    /**
     * Dispose the client (no more reconnects).
     */
    dispose(): void {
        this.disposed = true;
        this.disconnect();
        this.emitter.dispose();
        this.refreshEmitter.dispose();
    }
}
