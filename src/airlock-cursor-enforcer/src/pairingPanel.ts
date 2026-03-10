import * as vscode from "vscode";
import QRCode from "qrcode";
import {
    type PairingSession,
    type PairingResponse,
    pollPairingStatus,
    verifyPairingResponse,
    computeFingerprint,
    storePairedKey,
} from "./pairingClient.js";
import {
    storeEncryptionKey,
    storeRoutingToken,
    storeX25519KeyPair,
    deriveSharedKey,
    type X25519KeyPair,
} from "./crypto.js";

/**
 * Manage the QR + Text Code pairing Webview panel.
 * Displays QR image + copyable text code, polls Gateway, and handles completion.
 */
export class PairingPanel {
    private readonly panel: vscode.WebviewPanel;
    private pollTimer: ReturnType<typeof setInterval> | undefined;
    private disposed = false;
    /** Shared encryption key generated during this pairing session */
    private readonly encryptionKey: string;
    /** X25519 keypair for ECDH key agreement (Phase 3) */
    private readonly x25519KeyPair: X25519KeyPair;
    /** Human-readable label for this enforcer instance */
    private readonly enforcerLabel: string;
    /** Workspace name for display on mobile */
    private readonly workspaceName: string;
    /** JWT token for gateway authentication */
    private readonly token?: string;

    /** Optional callback invoked when pairing completes successfully */
    private readonly onComplete?: () => void;

    constructor(
        private readonly session: PairingSession,
        private readonly context: vscode.ExtensionContext,
        private readonly out: vscode.OutputChannel,
        encryptionKey: string,
        x25519KeyPair: X25519KeyPair,
        enforcerLabel: string,
        workspaceName: string,
        onComplete?: () => void,
        token?: string,
    ) {
        // Accept pre-generated keys (generated in extension.ts before initiation
        // so they are also sent to Gateway for code-based pairing support)
        this.x25519KeyPair = x25519KeyPair;
        this.encryptionKey = encryptionKey;
        this.enforcerLabel = enforcerLabel;
        this.workspaceName = workspaceName;
        this.onComplete = onComplete;
        this.token = token;
        this.out.appendLine(`[Airlock Pairing] Using pre-generated X25519 keypair + fallback symmetric key`);

        this.panel = vscode.window.createWebviewPanel(
            "airlockPairing",
            "Airlock — Pair Mobile Approver",
            vscode.ViewColumn.One,
            { enableScripts: true }
        );

        this.panel.onDidDispose(() => {
            this.disposed = true;
            this.stopPolling();
        });

        // Generate QR and render
        this.initPanel();
    }

    private async initPanel(): Promise<void> {
        this.panel.webview.html = await this.buildHtml();
        this.startPolling();
    }

    private startPolling(): void {
        this.out.appendLine("[Airlock Pairing] Polling for completion...");

        this.pollTimer = setInterval(async () => {
            if (this.disposed) { return; }

            try {
                const status = await pollPairingStatus(
                    this.session.localGatewayUrl,
                    this.session.pairingNonce,
                    this.token
                );

                if (status.state === "Completed" && status.responseJson) {
                    this.stopPolling();
                    await this.handleCompletion(status.responseJson, status.routingToken);
                } else if (status.state === "Expired") {
                    this.stopPolling();
                    this.out.appendLine("[Airlock Pairing] Session expired.");
                    this.panel.webview.html = this.buildExpiredHtml();
                }
            } catch (err) {
                this.out.appendLine(`[Airlock Pairing] Poll error: ${err}`);
            }
        }, 2000);
    }

    private stopPolling(): void {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = undefined;
        }
    }

    private async handleCompletion(responseJson: string, routingToken: string | null): Promise<void> {
        this.out.appendLine("[Airlock Pairing] Pairing response received.");

        let response: PairingResponse;
        try {
            response = JSON.parse(responseJson);
        } catch {
            vscode.window.showErrorMessage("Airlock: Invalid pairing response JSON.");
            return;
        }

        // Verify signature
        const valid = verifyPairingResponse(response, this.out);
        if (!valid) {
            this.out.appendLine("[Airlock Pairing] ✗ Signature verification failed!");
            vscode.window.showErrorMessage(
                "Airlock: Pairing failed — signature verification failed. Possible tampering."
            );

            // Revoke the pairing on the Gateway so mobile app doesn't think it's still paired
            if (routingToken) {
                try {
                    const revokeUrl = `${this.session.localGatewayUrl}/v1/pairing/revoke`;
                    const resp = await fetch(revokeUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            ...(this.token ? { "Authorization": `Bearer ${this.token}` } : {})
                        },
                        body: JSON.stringify({ routingToken }),
                    });
                    this.out.appendLine(`[Airlock Pairing] ✓ Revoked pairing on Gateway (${resp.status})`);
                } catch (err) {
                    this.out.appendLine(`[Airlock Pairing] ⚠ Revoke failed (non-fatal): ${err}`);
                }
            }

            this.panel.dispose();
            return;
        }

        this.out.appendLine("[Airlock Pairing] ✓ Signature verified.");

        // Show fingerprint for manual confirmation
        const fingerprint = computeFingerprint(response.publicKey);
        const confirm = await vscode.window.showInformationMessage(
            `Airlock: Pair with Mobile Approver?\n\nPublic key fingerprint: ${fingerprint}\nSigner key ID: ${response.signerKeyId}`,
            { modal: true },
            "Confirm Pairing",
            "Decline Pairing"
        );

        if (confirm === "Confirm Pairing") {
            await storePairedKey(
                this.context,
                response.signerKeyId,
                response.publicKey,
                this.session.deviceId
            );
            // Phase 3: Derive shared key via X25519 ECDH if mobile sent its pubkey
            const mobileX25519PubKey = response.x25519PublicKey;
            let derivedEncryptionKey: string;

            if (mobileX25519PubKey) {
                // ECDH: derive shared secret from our privkey + mobile's pubkey
                derivedEncryptionKey = deriveSharedKey(this.x25519KeyPair.privateKey, mobileX25519PubKey);
                this.out.appendLine(`[Airlock Pairing] ✓ X25519 ECDH key agreement completed (HARP-KEYMGMT §2.3)`);
            } else {
                // Fallback: use the random symmetric key sent in QR (Phase 1 compat)
                derivedEncryptionKey = this.encryptionKey;
                this.out.appendLine(`[Airlock Pairing] ⚠ Mobile doesn't support ECDH — using fallback symmetric key`);
            }

            await storeEncryptionKey(this.context, derivedEncryptionKey);
            await storeX25519KeyPair(this.context, this.x25519KeyPair);
            // Store opaque routing token for privacy-preserving routing
            if (routingToken) {
                await storeRoutingToken(this.context, routingToken);
                this.out.appendLine(`[Airlock Pairing] ✓ Routing token stored (${routingToken.length} chars)`);
            } else {
                this.out.appendLine(`[Airlock Pairing] ⚠ No routing token received from Gateway in /status response!`);
            }
            this.out.appendLine(`[Airlock Pairing] ✓ Paired! keyId=${response.signerKeyId} fingerprint=${fingerprint}`);
            this.out.appendLine(`[Airlock Pairing] ✓ E2E encryption key stored — artifacts will now be encrypted`);
            vscode.window.showInformationMessage(`Airlock: Paired successfully! Fingerprint: ${fingerprint}`);
            this.onComplete?.();
        } else {
            this.out.appendLine("[Airlock Pairing] ✗ User rejected pairing.");
            vscode.window.showWarningMessage("Airlock: Pairing rejected by user.");

            // Revoke the pairing on the Gateway so mobile app doesn't think it's still paired
            if (routingToken) {
                try {
                    const revokeUrl = `${this.session.localGatewayUrl}/v1/pairing/revoke`;
                    const resp = await fetch(revokeUrl, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            ...(this.token ? { "Authorization": `Bearer ${this.token}` } : {})
                        },
                        body: JSON.stringify({ routingToken }),
                    });
                    this.out.appendLine(`[Airlock Pairing] ✓ Revoked pairing on Gateway (${resp.status})`);
                } catch (err) {
                    this.out.appendLine(`[Airlock Pairing] ⚠ Revoke failed (non-fatal): ${err}`);
                }
            }
        }

        this.panel.dispose();
    }

    private async buildHtml(): Promise<string> {
        const qrPayload = JSON.stringify({
            deviceId: this.session.deviceId,
            pairingNonce: this.session.pairingNonce,
            gatewayUrl: this.session.gatewayUrl,
            expiresAt: this.session.expiresAt,
            // Phase 1: symmetric key fallback for mobile apps that don't support ECDH
            encryptionKey: this.encryptionKey,
            // Phase 3: X25519 public key for ECDH key agreement
            x25519PublicKey: this.x25519KeyPair.publicKey,
            // Human-readable label for this enforcer instance
            enforcerLabel: this.enforcerLabel,
            // Workspace name for mobile display
            workspaceName: this.workspaceName,
        });

        const expiresMs = new Date(this.session.expiresAt).getTime();

        // Generate actual QR code as data URL (server-side via qrcode package)
        let qrDataUrl = "";
        try {
            qrDataUrl = await QRCode.toDataURL(qrPayload, {
                width: 256,
                margin: 2,
                color: { dark: "#000000", light: "#ffffff" },
                errorCorrectionLevel: "M",
            });
        } catch (err) {
            this.out.appendLine(`[Airlock Pairing] QR generation failed: ${err}`);
        }

        const qrHtml = qrDataUrl
            ? `<img src="${qrDataUrl}" alt="QR Code" style="width: 256px; height: 256px; image-rendering: pixelated; border-radius: 8px;" />`
            : `<div style="width: 256px; height: 256px; display: flex; align-items: center; justify-content: center; border: 2px dashed var(--vscode-descriptionForeground); border-radius: 8px; font-size: 13px; color: var(--vscode-descriptionForeground);">QR generation failed</div>`;

        return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Airlock Pairing</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex; flex-direction: column; align-items: center;
            padding: 24px; color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
        h2 { margin-bottom: 8px; }
        .subtitle { color: var(--vscode-descriptionForeground); margin-bottom: 24px; }
        .code-box {
            display: flex; align-items: center; gap: 12px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-input-border);
            border-radius: 6px; padding: 12px 20px;
            font-size: 28px; font-family: 'Cascadia Code', monospace;
            letter-spacing: 6px; font-weight: bold;
        }
        .copy-btn {
            cursor: pointer; font-size: 14px; padding: 4px 10px;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none; border-radius: 4px;
        }
        .copy-btn:hover { background: var(--vscode-button-hoverBackground); }
        .timer { margin: 16px 0; font-size: 14px; color: var(--vscode-descriptionForeground); }
        .spinner { animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .status { display: flex; align-items: center; gap: 8px; margin-top: 16px; }
    </style>
</head>
<body>
    <h2>🔗 Pair Mobile Approver</h2>
    <p class="subtitle">Scan the QR code or enter the pairing code in your mobile app</p>

    ${qrHtml}

    <p style="margin: 12px 0 4px; font-size: 13px; color: var(--vscode-descriptionForeground);">
        Or enter this code manually:
    </p>
    <div class="code-box">
        <span id="code">${this.session.pairingCode}</span>
        <button class="copy-btn" onclick="navigator.clipboard.writeText('${this.session.pairingCode}')">Copy</button>
    </div>

    <div class="timer" id="timer"></div>

    <div class="status">
        <span class="spinner">◉</span>
        <span>Waiting for Mobile Approver...</span>
    </div>

    <script>
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

    private buildExpiredHtml(): string {
        return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: -apple-system, sans-serif;
            display: flex; flex-direction: column; align-items: center;
            padding: 48px; color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
        }
    </style>
</head>
<body>
    <h2>⏰ Session Expired</h2>
    <p>The pairing session has expired. Please close this panel and start a new pairing.</p>
</body>
</html>`;
    }
}
