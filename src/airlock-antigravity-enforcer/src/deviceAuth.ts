import * as vscode from 'vscode';
import { EventEmitter } from 'events';

const SECRET_ACCESS_TOKEN = 'airlock.accessToken';
const SECRET_REFRESH_TOKEN = 'airlock.refreshToken';
const SECRET_GATEWAY_URL = 'airlock.gatewayUrl';

/**
 * OAuth2 Device Authorization flow for Keycloak, proxied through the Gateway.
 * Same UX as `gh auth login` — opens browser, user logs in, extension gets tokens.
 */
export class DeviceAuth {
    private accessToken: string | undefined;
    private refreshToken: string | undefined;
    private gatewayUrl: string | undefined;
    private readonly _authEmitter = new EventEmitter();
    private static readonly MAX_REFRESH_RETRIES = 10;

    constructor(private readonly secrets: vscode.SecretStorage) { }

    get token(): string | undefined { return this.accessToken; }
    get gateway(): string | undefined { return this.gatewayUrl; }
    get isLoggedIn(): boolean { return !!this.accessToken; }

    /** Restore tokens from SecretStorage. Returns true if a valid session was restored. */
    async restoreSession(): Promise<boolean> {
        this.accessToken = await this.secrets.get(SECRET_ACCESS_TOKEN);
        this.refreshToken = await this.secrets.get(SECRET_REFRESH_TOKEN);
        this.gatewayUrl = await this.secrets.get(SECRET_GATEWAY_URL);
        if (!this.accessToken) { return false; }

        // If access token is already expired, try to refresh eagerly
        if (this.isTokenExpired()) {
            return await this.refresh();
        }
        return true;
    }

    /** Full login flow: optionally prompt for gateway URL → start device auth → open browser → poll for tokens.
     *  If resolvedGatewayUrl is provided, skip the URL prompt (prod builds use the hardcoded gateway).
     */
    async login(resolvedGatewayUrl?: string): Promise<boolean> {
        // 1. Get Gateway URL — skip prompt if resolved URL is provided
        let gatewayUrl = resolvedGatewayUrl;
        if (!gatewayUrl) {
            gatewayUrl = await vscode.window.showInputBox({
                title: 'Airlock Gateway URL',
                prompt: 'Enter the Gateway URL (e.g. https://localhost:7145)',
                value: this.gatewayUrl || 'https://localhost:7145',
                validateInput: (v) => v.startsWith('http') ? null : 'Must start with http:// or https://'
            });
        }
        if (!gatewayUrl) { return false; }

        // 2. Start device authorization
        const startResp = await this.postJson(`${gatewayUrl}/v1/auth/device`, {});
        if (!startResp) {
            vscode.window.showErrorMessage('Failed to start device authorization. Is the Gateway running?');
            return false;
        }

        const { deviceCode, userCode, verificationUri, verificationUriComplete, expiresIn, interval } = startResp;
        const loginUrl = verificationUriComplete || verificationUri;

        // 3. Show user code in a webview panel with copy button
        const panel = vscode.window.createWebviewPanel(
            'airlockDeviceAuth',
            'Airlock — Sign In',
            vscode.ViewColumn.One,
            { enableScripts: true }
        );

        const expiresMs = Date.now() + (expiresIn || 600) * 1000;
        panel.webview.html = this.buildDeviceAuthHtml(userCode, loginUrl, expiresMs);

        // Handle messages from webview
        panel.webview.onDidReceiveMessage(async (msg) => {
            if (msg.command === 'openBrowser') {
                await vscode.env.openExternal(vscode.Uri.parse(loginUrl));
            }
        });

        // 4. Poll for token
        return await vscode.window.withProgress(
            { location: vscode.ProgressLocation.Notification, title: 'Waiting for login...', cancellable: true },
            async (progress, cancelToken) => {
                const pollInterval = (interval || 5) * 1000;
                const deadline = Date.now() + (expiresIn || 600) * 1000;

                while (Date.now() < deadline) {
                    if (cancelToken.isCancellationRequested) { return false; }

                    await this.sleep(pollInterval);

                    const pollResp = await this.postJson(`${gatewayUrl}/v1/auth/device/token`, { deviceCode });
                    if (!pollResp) { continue; }

                    if (pollResp.completed) {
                        this.accessToken = pollResp.accessToken;
                        this.refreshToken = pollResp.refreshToken;
                        this.gatewayUrl = gatewayUrl;

                        await this.secrets.store(SECRET_ACCESS_TOKEN, this.accessToken!);
                        await this.secrets.store(SECRET_REFRESH_TOKEN, this.refreshToken!);
                        await this.secrets.store(SECRET_GATEWAY_URL, gatewayUrl);

                        panel.dispose();
                        vscode.window.showInformationMessage('✅ Airlock: Signed in successfully!');
                        return true;
                    }

                    if (pollResp.error === 'authorization_pending' || pollResp.error === 'slow_down') {
                        continue; // Keep polling
                    }

                    // expired_token, access_denied, or other error
                    panel.dispose();
                    vscode.window.showErrorMessage(`Login failed: ${pollResp.error}`);
                    return false;
                }

                panel.dispose();
                vscode.window.showErrorMessage('Login timed out. Please try again.');
                return false;
            }
        );
    }

    /** Refresh the access token using the stored refresh token. */
    async refresh(): Promise<boolean> {
        if (!this.refreshToken || !this.gatewayUrl) { return false; }

        const resp = await this.postJson(`${this.gatewayUrl}/v1/auth/enforcer/refresh`, {
            refreshToken: this.refreshToken
        });

        if (!resp || !resp.accessToken) {
            // Don't call logout() — keep tokens for future retry.
            // The failure may be transient (gateway down, temporary network issue).
            return false;
        }

        this.accessToken = resp.accessToken;
        this.refreshToken = resp.refreshToken;
        await this.secrets.store(SECRET_ACCESS_TOKEN, this.accessToken!);
        await this.secrets.store(SECRET_REFRESH_TOKEN, this.refreshToken!);
        return true;
    }

    /**
     * Returns a fresh access token, refreshing if the current one expires within 60s.
     * Used by the named pipe proxy before forwarding gateway requests.
     */
    async ensureFreshToken(): Promise<string | undefined> {
        if (!this.accessToken) { return undefined; }

        // Parse JWT exp claim
        try {
            const payload = JSON.parse(Buffer.from(this.accessToken.split('.')[1], 'base64url').toString('utf8'));
            const expiresAt = (payload.exp as number) * 1000; // ms
            const refreshAt = expiresAt - 60_000; // 60s before expiry
            if (Date.now() >= refreshAt) {
                const ok = await this.refresh();
                if (!ok) { return undefined; }
            }
        } catch {
            // Malformed JWT — try raw refresh
            await this.refresh();
        }

        return this.accessToken;
    }

    /**
     * Starts a timer that proactively refreshes the JWT ~60s before it expires.
     * Call this after restoring a session or completing login.
     * Returns a Disposable that clears the timer.
     */
    /**
     * Subscribe to auth state changes.
     * Listener receives `true` when token is refreshed, `false` when refresh fails.
     */
    onAuthStateChanged(listener: (loggedIn: boolean) => void): { dispose(): void } {
        this._authEmitter.on('change', listener);
        return { dispose: () => { this._authEmitter.off('change', listener); } };
    }

    /**
     * Subscribe to permanent session expiry.
     * Fires when the refresh token is permanently dead (max retries exhausted).
     * The extension should prompt the user to re-login.
     */
    onSessionExpired(listener: () => void): { dispose(): void } {
        this._authEmitter.on('session_expired', listener);
        return { dispose: () => { this._authEmitter.off('session_expired', listener); } };
    }

    startRefreshTimer(): { dispose(): void } {
        let timer: ReturnType<typeof setTimeout> | undefined;
        let retryCount = 0;

        const scheduleNext = () => {
            if (!this.accessToken) { return; }
            try {
                const payload = JSON.parse(Buffer.from(this.accessToken.split('.')[1], 'base64url').toString('utf8'));
                const expiresAt = (payload.exp as number) * 1000;
                const refreshAt = expiresAt - 60_000;
                const delay = Math.max(0, refreshAt - Date.now());
                timer = setTimeout(async () => {
                    const ok = await this.refresh();
                    if (ok) {
                        retryCount = 0;
                        this._authEmitter.emit('change', true);
                        scheduleNext(); // Schedule next refresh
                    } else {
                        retryCount++;
                        if (retryCount >= DeviceAuth.MAX_REFRESH_RETRIES) {
                            // Permanent failure — session is dead, prompt re-login
                            this._authEmitter.emit('change', false);
                            this._authEmitter.emit('session_expired');
                            return; // Stop retrying
                        }
                        // Retry with exponential backoff: 30s, 60s, 120s, 240s, max 300s
                        const retryDelay = Math.min(30_000 * Math.pow(2, retryCount - 1), 300_000);
                        this._authEmitter.emit('change', false);
                        timer = setTimeout(() => scheduleNext(), retryDelay);
                    }
                }, delay);
            } catch { /* ignore malformed JWT */ }
        };

        scheduleNext();
        return { dispose: () => { if (timer) { clearTimeout(timer); } } };
    }


    /** Check if the current access token is expired. */
    private isTokenExpired(): boolean {
        if (!this.accessToken) { return true; }
        try {
            const payload = JSON.parse(
                Buffer.from(this.accessToken.split('.')[1], 'base64url').toString('utf8')
            );
            return Date.now() >= (payload.exp as number) * 1000;
        } catch { return true; }
    }

    /** Clear all stored tokens. */
    async logout(): Promise<void> {
        this.accessToken = undefined;
        this.refreshToken = undefined;
        this.gatewayUrl = undefined;
        await this.secrets.delete(SECRET_ACCESS_TOKEN);
        await this.secrets.delete(SECRET_REFRESH_TOKEN);
        await this.secrets.delete(SECRET_GATEWAY_URL);
    }

    // ── Device Auth Panel HTML ──────────────────────────────────────

    private buildDeviceAuthHtml(_userCode: string, loginUrl: string, expiresMs: number): string {
        return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Airlock Sign In</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex; flex-direction: column; align-items: center;
            padding: 32px; color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        h2 { margin-bottom: 8px; }
        .subtitle { color: var(--vscode-descriptionForeground); margin-bottom: 24px; font-size: 14px; }
        .open-btn {
            cursor: pointer; font-size: 14px; padding: 10px 24px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none; border-radius: 6px;
            margin-top: 16px; font-weight: 600;
        }
        .open-btn:hover { background: var(--vscode-button-hoverBackground); }
        .timer { margin: 16px 0; font-size: 13px; color: var(--vscode-descriptionForeground); }
        .url-hint {
            font-size: 12px; color: var(--vscode-descriptionForeground);
            word-break: break-all; margin: 12px 0 0;
            max-width: 500px; text-align: center;
        }
        .spinner { animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .status { display: flex; align-items: center; gap: 8px; margin-top: 16px; font-size: 14px; }
        .steps {
            margin-top: 24px; padding: 16px 24px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-input-border);
            border-radius: 8px; font-size: 13px; line-height: 2;
            text-align: left;
        }
        .steps ol { margin: 0; padding-left: 20px; }
        .steps li { color: var(--vscode-descriptionForeground); }
    </style>
</head>
<body>
    <h2>🔐 Sign In to Airlock</h2>
    <p class="subtitle">Click the button below to open the login page in your browser</p>

    <button class="open-btn" id="openBtn">🌐 Open Browser to Sign In</button>

    <p class="url-hint">${loginUrl}</p>

    <div class="timer" id="timer"></div>

    <div class="steps">
        <ol>
            <li>Click <strong>Open Browser to Sign In</strong></li>
            <li>Sign in with your credentials</li>
            <li>This panel will close automatically once authenticated</li>
        </ol>
    </div>

    <div class="status">
        <span class="spinner">◉</span>
        <span>Waiting for authentication...</span>
    </div>

    <script>
    const vscode = acquireVsCodeApi();

    // Open Browser button
    document.getElementById('openBtn').addEventListener('click', () => {
        vscode.postMessage({ command: 'openBrowser' });
    });

    // Countdown timer
    const expiresMs = ${expiresMs};
    const timerEl = document.getElementById('timer');
    const updateTimer = () => {
        const remaining = Math.max(0, expiresMs - Date.now());
        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        timerEl.textContent = remaining > 0
            ? 'Expires in ' + minutes + ':' + String(seconds).padStart(2, '0')
            : 'Session expired';
    };
    updateTimer();
    setInterval(updateTimer, 1000);
    </script>
</body>
</html>`;
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private async postJson(url: string, body: object): Promise<any | null> {
        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (!resp.ok && resp.status !== 200) { return null; }
            return await resp.json();
        } catch {
            return null;
        }
    }

    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}
