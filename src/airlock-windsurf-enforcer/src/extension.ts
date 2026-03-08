import * as vscode from "vscode";
import { resolveEndpoint, type EndpointInfo } from "./endpointResolver.js";
import {
    createToggleStatusBarItem,
    createApprovalStatusBarItem,
    createSignInStatusBarItem,
    updateToggleStatusBar,
    updateSignInStatusBar,
    type SignInState,
} from "./statusBar.js";
import { AutoModeController } from "./autoMode.js";
import { HooksDetectionStrategy } from "./hooksStrategy.js";
import { initiatePairing } from "./pairingClient.js";
import { PairingPanel } from "./pairingPanel.js";
import type { DetectionConfig } from "./detectionStrategy.js";
import { getRoutingToken, clearRoutingToken, clearEncryptionKey, getEncryptionKey } from "./crypto.js";
import { PresenceClient } from "./presenceClient.js";
import { DeviceAuth } from "./deviceAuth.js";
import { NamedPipeProxy } from "./namedPipeProxy.js";

let endpoint: EndpointInfo | null = null;
let pairingStatusBarItem: vscode.StatusBarItem;
let presenceClient: PresenceClient | null = null;
let deviceAuth: DeviceAuth;
let _pipeProxy: NamedPipeProxy | null = null;
let _refreshTimer: { dispose(): void } | null = null;
let _quotaTimer: ReturnType<typeof setInterval> | null = null;

const LOCAL_SECRET = NamedPipeProxy.generateLocalSecret();

/**
 * Get or auto-generate a persistent enforcerId.
 * Priority: config setting > workspaceState (auto-generated) > generate new UUID.
 * Stored per-workspace so each VS Code instance has its own presence identity.
 */
function getOrCreateEnforcerId(context: vscode.ExtensionContext): string {
    // User-configured value takes priority
    const configured = vscode.workspace.getConfiguration("airlock").get<string>("enforcerId");
    if (configured) { return configured; }

    // Auto-generated, persisted per-workspace
    const stored = context.workspaceState.get<string>("airlock.enforcerId");
    if (stored) { return stored; }

    // First activation in this workspace — generate and persist
    const generated = `enf-${crypto.randomUUID()}`;
    context.workspaceState.update("airlock.enforcerId", generated);
    return generated;
}

export function activate(context: vscode.ExtensionContext) {
    const out = vscode.window.createOutputChannel("Airlock Windsurf");
    const enforcerId = getOrCreateEnforcerId(context);
    out.appendLine(`Airlock Windsurf Enforcer v2 activated. EnforcerId: ${enforcerId}`);
    out.show(true);

    // ── TLS configuration ─────────────────────────────────────
    // Allow self-signed certs only when explicitly enabled in settings.
    const applyTlsConfig = () => {
        const allow = vscode.workspace.getConfiguration("airlock").get<boolean>("allowSelfSignedCerts", false);
        process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = allow ? "0" : "1";
        out.appendLine(`[Airlock] TLS: ${allow ? "self-signed certs allowed (allowSelfSignedCerts=true)" : "strict TLS (allowSelfSignedCerts=false)"}`);
    };
    applyTlsConfig();

    // Re-apply if user changes the setting while the extension is running
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration("airlock.allowSelfSignedCerts")) {
                applyTlsConfig();
                if (presenceClient && endpoint) {
                    presenceClient.disconnect();
                    const token = getRoutingToken(context);
                    if (token) {
                        presenceClient.connect(endpoint.url, () => deviceAuth?.token, enforcerId);
                    }
                }
            }
            // Re-write hooks wrapper when auto-approve patterns change
            if (e.affectsConfiguration("airlock.autoApprovePatterns")) {
                if (strategy) {
                    out.appendLine("[Airlock] autoApprovePatterns changed — rewriting hooks wrappers");
                    strategy.reinstallHooks().catch(() => { /* non-fatal */ });
                }
            }
        })
    );

    // ── One-time migration: clear old globalState pairing data ──────
    // Before Sprint 18_3b, pairing state was stored in globalState (shared
    // across all workspaces). Now it's in workspaceState. Clear the old
    // global keys so stale pairings don't leak into unrelated workspaces.
    const migrationKey = "airlock.migrated.workspaceState.v1";
    if (!context.globalState.get<boolean>(migrationKey)) {
        const oldKeys = ["airlock.routingToken", "airlock.pairedKeys",
            "airlock.x25519PublicKey", "airlock.pairedKeyId", "airlock.pairedPublicKey"];
        for (const key of oldKeys) {
            context.globalState.update(key, undefined);
        }
        // Also clear old unscoped encryption key from SecretStorage
        context.secrets.delete("airlock.encryptionKey");
        context.secrets.delete("airlock.x25519PrivateKey");
        context.globalState.update(migrationKey, true);
        out.appendLine("[Airlock] ✓ Migrated: cleared old global pairing state. Please re-pair in this workspace.");
    }

    // ── Status Bar Items ─────────────────────────────────────────
    const toggleItem = createToggleStatusBarItem();
    context.subscriptions.push(toggleItem);

    const approvalItem = createApprovalStatusBarItem();
    context.subscriptions.push(approvalItem);

    // ── Auth status bar (sign-in indicator + quota warnings) ──────
    const signInStatusBarItem = createSignInStatusBarItem();
    context.subscriptions.push(signInStatusBarItem);

    // ── Pairing Status Bar ────────────────────────────────────
    pairingStatusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right, 98
    );
    pairingStatusBarItem.command = "airlock.startPairing";
    context.subscriptions.push(pairingStatusBarItem);
    updatePairingStatusBar(context);
    pairingStatusBarItem.show();


    // ── Auto-Mode Controller ───────────────────────────────────
    const autoMode = new AutoModeController(
        out,
        toggleItem,
        approvalItem,
        context,
        () => endpoint
    );
    context.subscriptions.push(autoMode);

    // ── Configuration ──────────────────────────────────────────
    const getConfig = (): DetectionConfig => {
        const cfg = vscode.workspace.getConfiguration("airlock");
        return {
            autoApprovePatterns: cfg.get<string[]>("autoApprovePatterns", []),
        };
    };

    // ── Initialization ─────────────────────────────────────────
    let strategy: HooksDetectionStrategy | null = null;

    const init = async () => {
        endpoint = await resolveEndpoint(out, context.extension.packageJSON.name);

        if (endpoint) {
            out.appendLine(`[Airlock] Endpoint: ${endpoint.url} (${endpoint.source})`);
        } else {
            updateToggleStatusBar(toggleItem, "no-endpoint");
        }

        // ── Named Pipe Proxy (JWT ↔ gate script bridge) ─────────────
        if (!deviceAuth) { deviceAuth = new DeviceAuth(context.secrets); }
        const pipeName = NamedPipeProxy.getPipeName(enforcerId);
        if (!_pipeProxy) {
            _pipeProxy = new NamedPipeProxy({
                enforcerId, gatewayUrl: endpoint?.url ?? "", localSecret: LOCAL_SECRET,
                auth: () => deviceAuth,
                getEncryptionKey: () => getEncryptionKey(context),
                log: (msg) => out.appendLine(`[Airlock Pipe] ${msg}`),
                onQuotaExceeded: (errorCode) => {
                    out.appendLine(`[Airlock Pipe] ⚠ Quota exceeded event: ${errorCode}`);
                    updateSignInStatusBar(signInStatusBarItem, {
                        status: "quota-warning",
                        workspacesUsed: -1, workspacesLimit: -1,
                    });
                    vscode.window.showWarningMessage(
                        `Airlock: Plan quota exceeded (${errorCode}). Requests are being allowed (fail-open) but you may need to upgrade your plan.`
                    );
                },
            });
            try { await _pipeProxy.start(); } catch (e) { out.appendLine(`[Airlock Pipe] Failed: ${e}`); }
            context.subscriptions.push({ dispose: () => { _pipeProxy?.stop(); _pipeProxy = null; } });
        }

        // ── Hooks strategy (Windsurf native) ──────────────────────────
        out.appendLine(`[Airlock] Detection strategy: hooks`);
        out.appendLine(`[Airlock IDE] appName="${vscode.env.appName}" sessionId=${vscode.env.sessionId.substring(0, 8)}`);

        strategy = new HooksDetectionStrategy(
            out, context, enforcerId, endpoint?.url ?? "",
            pipeName, LOCAL_SECRET,
        );

        context.subscriptions.push(strategy);
        await autoMode.setStrategy(strategy, getConfig());

        if (autoMode.isEnabled) {
            updateToggleStatusBar(toggleItem, "on");
        } else if (endpoint) {
            updateToggleStatusBar(toggleItem, "connected");
        }

        // ── Presence Client ────────────────────────────────────
        if (endpoint) {
            presenceClient = new PresenceClient(out, "2.0.0", "Windsurf");
            context.subscriptions.push({ dispose: () => presenceClient?.dispose() });

            presenceClient.onEvent(async (event) => {
                if (event === "connected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "disconnected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "pairing.revoked") {
                    out.appendLine("[Airlock] Pairing revoked by admin. Stopping proxy and clearing pairing state.");
                    // Stop the pipe proxy so the gate script fails open until re-paired
                    _pipeProxy?.stop();
                    _pipeProxy = null;
                    await clearRoutingToken(context);
                    await clearEncryptionKey(context);
                    updatePairingStatusBar(context);
                    if (strategy) {
                        try { await strategy.reinstallHooks(); } catch { /* non-fatal */ }
                    }
                    vscode.window.showWarningMessage(
                        "Airlock: This pairing was revoked by an admin. Hooks are now inactive \u2014 re-pair to resume enforcement."
                    );
                }
            });

            // Restore auth session
            if (!deviceAuth) { deviceAuth = new DeviceAuth(context.secrets); }
            const restored = await deviceAuth.restoreSession();
            if (restored) {
                // Fetch quota status and update sign-in item
                await checkAndUpdateQuota(signInStatusBarItem, out);
                // Start periodic quota check
                context.subscriptions.push(startQuotaTimer(signInStatusBarItem, out));
                _refreshTimer?.dispose();
                _refreshTimer = deviceAuth.startRefreshTimer();
                context.subscriptions.push({ dispose: () => { _refreshTimer?.dispose(); } });
                context.subscriptions.push(
                    deviceAuth.onAuthStateChanged((loggedIn) => {
                        if (loggedIn) {
                            updateSignInStatusBar(signInStatusBarItem, { status: "signed-in" });
                            checkAndUpdateQuota(signInStatusBarItem, out);
                            if (presenceClient && endpoint) {
                                presenceClient.disconnect();
                                presenceClient.connect(endpoint.url, () => deviceAuth?.token, enforcerId);
                            }
                        } else {
                            updateSignInStatusBar(signInStatusBarItem, { status: "not-signed-in" });
                        }
                    })
                );
                context.subscriptions.push(
                    deviceAuth.onSessionExpired(() => {
                        out.appendLine('[Airlock] ⚠ Session expired — refresh token is permanently invalid. Prompting re-login.');
                        updateSignInStatusBar(signInStatusBarItem, { status: "not-signed-in" });
                        vscode.window.showWarningMessage(
                            'Airlock: Your session has expired. Please sign in again to continue.',
                            'Sign In'
                        ).then(choice => {
                            if (choice === 'Sign In') {
                                vscode.commands.executeCommand('airlock.login');
                            }
                        });
                    })
                );
            } else {
                updateSignInStatusBar(signInStatusBarItem, { status: "not-signed-in" });
            }
            presenceClient.connect(endpoint.url, () => deviceAuth?.token, enforcerId);
        }
    };

    init().catch((err) => {
        out.appendLine(`[Airlock] Init error: ${err}`);
    });

    // ── Helper: ensure presence connected ───────────────────────
    const ensurePresenceConnected = async () => {
        if (!endpoint) { return; }
        if (!deviceAuth) {
            deviceAuth = new DeviceAuth(context.secrets);
            await deviceAuth.restoreSession();
        }
        if (!presenceClient) {
            presenceClient = new PresenceClient(out, "2.0.0", "Windsurf");
            context.subscriptions.push({ dispose: () => presenceClient?.dispose() });
            presenceClient.onEvent(async (event) => {
                if (event === "connected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "disconnected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "pairing.revoked") {
                    out.appendLine("[Airlock] Pairing revoked by admin. Stopping proxy and clearing pairing state.");
                    _pipeProxy?.stop();
                    _pipeProxy = null;
                    await clearRoutingToken(context);
                    await clearEncryptionKey(context);
                    updatePairingStatusBar(context);
                    if (strategy) {
                        try { await strategy.reinstallHooks(); } catch { /* non-fatal */ }
                    }
                    vscode.window.showWarningMessage(
                        "Airlock: This pairing was revoked by an admin. Hooks are now inactive \u2014 re-pair to resume enforcement."
                    );
                }
            });
        }
        presenceClient.connect(endpoint.url, () => deviceAuth?.token, enforcerId);
        out.appendLine(`[Airlock Presence] Connecting to ${endpoint.url}`);
    };

    // ── Helper: ensure endpoint ────────────────────────────────
    const requireEndpoint = (): string | null => {
        if (endpoint) { return endpoint.url; }
        vscode.window.showWarningMessage(
            'Airlock: No endpoint configured. Use "Configure Endpoint" to set one.'
        );
        return null;
    };

    // ── Helper: ensure device auth ──────────────────────────────
    const requireAuth = async (): Promise<boolean> => {
        if (!deviceAuth) {
            out.appendLine('[Airlock] requireAuth: creating new DeviceAuth');
            deviceAuth = new DeviceAuth(context.secrets);
            await deviceAuth.restoreSession();
        }
        if (deviceAuth.isLoggedIn) {
            out.appendLine('[Airlock] requireAuth: already logged in');
            return true;
        }
        // Try restoring in case tokens were stored after init
        await deviceAuth.restoreSession();
        if (deviceAuth.isLoggedIn) {
            out.appendLine('[Airlock] requireAuth: session restored');
            return true;
        }
        out.appendLine('[Airlock] requireAuth: NOT logged in — prompting');
        const login = await vscode.window.showInformationMessage(
            'Airlock: You need to sign in before you can do this.',
            { modal: true, detail: 'Sign in to connect your extension to the Airlock Gateway.' },
            'Sign In'
        );
        if (login === 'Sign In') {
            return await deviceAuth.login();
        }
        return false;
    };

    // ── Helper: ensure paired ───────────────────────────────────
    const requirePairing = (): boolean => {
        const token = getRoutingToken(context);
        if (token) { return true; }
        vscode.window.showWarningMessage(
            'Airlock: Not paired with a mobile approver. Pair first.',
            'Pair Now'
        ).then(choice => {
            if (choice === 'Pair Now') {
                vscode.commands.executeCommand('airlock.startPairing');
            }
        });
        return false;
    };

    // ── Command: Toggle Auto Mode ──────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.toggleAutoMode", async () => {
            if (autoMode.isEnabled) {
                await autoMode.disable();
            } else {
                if (!await requireAuth()) { return; }
                if (!requirePairing()) { return; }
                await autoMode.enable(getConfig());
            }
        })
    );

    // ── Command: Enable Auto Mode ──────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.enableAutoMode", async () => {
            if (!await requireAuth()) { return; }
            if (!requirePairing()) { return; }
            await autoMode.enable(getConfig());
        })
    );

    // ── Command: Disable Auto Mode ─────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.disableAutoMode", async () => {
            await autoMode.disable();
        })
    );




    // ── Command: Show Status ───────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.showStatus", async () => {
            const epStr = endpoint
                ? `${endpoint.url} (${endpoint.source})`
                : "Not configured";
            out.appendLine("\n==============================");
            out.appendLine("Airlock Status");
            out.appendLine("==============================");
            out.appendLine(`Endpoint: ${epStr}`);
            out.appendLine(`Strategy: ${autoMode.strategyName}`);
            out.appendLine(`Auto-Mode: ${autoMode.isEnabled ? "ON" : "OFF"}`);

            vscode.window.showInformationMessage(
                `Airlock: Endpoint=${epStr}, Strategy=${autoMode.strategyName}, Auto=${autoMode.isEnabled ? "ON" : "OFF"}`
            );
        })
    );

    // ── Command: Configure Endpoint ────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.configureEndpoint", async () => {
            const current = endpoint?.url ?? "";
            const input = await vscode.window.showInputBox({
                title: "Airlock: Configure Approval Endpoint",
                prompt: "Enter the Airlock Gateway URL (e.g. http://localhost:5100)",
                value: current,
                placeHolder: "http://127.0.0.1:7771",
            });

            if (input === undefined) { return; }

            if (input.trim()) {
                await vscode.workspace.getConfiguration("airlock")
                    .update("approvalEndpoint", input.trim(), vscode.ConfigurationTarget.Global);
                endpoint = { url: input.trim(), source: "setting" };
                updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                out.appendLine(`[Airlock] Endpoint set: ${input.trim()}`);
                // Connect presence if not yet connected
                await ensurePresenceConnected();
            } else {
                await vscode.workspace.getConfiguration("airlock")
                    .update("approvalEndpoint", undefined, vscode.ConfigurationTarget.Global);
                endpoint = await resolveEndpoint(out, context.extension.packageJSON.name);
                updateToggleStatusBar(toggleItem, endpoint ? "connected" : "no-endpoint");
            }
        })
    );




    // ── Command: Start Pairing ─────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.startPairing", async () => {
            const url = requireEndpoint();
            if (!url) { return; }
            if (!await requireAuth()) { return; }

            // Don't disable auto-mode — hooks keep detecting.
            // After pairing, new routing token will be used for submissions.

            const config = vscode.workspace.getConfiguration("airlock");
            const deviceId = config.get<string>("deviceId") || `dev-${Date.now()}`;

            try {
                // Generate keys before initiation so they're sent to Gateway for code-based pairing
                const { generateX25519KeyPair, generateEncryptionKey } = await import("./crypto.js");
                const x25519KeyPair = generateX25519KeyPair();
                const encryptionKey = generateEncryptionKey();

                // Human-readable label shown on mobile device during pairing
                const enforcerLabel = "Windsurf";
                const ws = vscode.workspace.workspaceFolders?.[0];
                const workspaceName = ws?.name ?? "unknown";

                const session = await initiatePairing(
                    url, deviceId, enforcerId, out,
                    x25519KeyPair.publicKey, enforcerLabel,
                    deviceAuth?.token, workspaceName
                );
                new PairingPanel(session, context, out, encryptionKey, x25519KeyPair, enforcerLabel, workspaceName,
                    async () => {
                        // Pairing completed — update status bar and re-enable auto-mode
                        // to clear _seenButtons so existing buttons are re-detected
                        // with the new routing token
                        updatePairingStatusBar(context);
                        out.appendLine("[Airlock Pairing] ✓ Paired — re-enabling auto-mode with new routing token.");

                        // Restart pipe proxy (may have been destroyed by pairing.revoked)
                        if (!_pipeProxy && endpoint) {
                            const pipeName = NamedPipeProxy.getPipeName(enforcerId);
                            _pipeProxy = new NamedPipeProxy({
                                enforcerId,
                                gatewayUrl: endpoint.url,
                                localSecret: LOCAL_SECRET,
                                auth: () => deviceAuth,
                                getEncryptionKey: () => getEncryptionKey(context),
                                log: (msg) => out.appendLine(`[Airlock Pipe] ${msg}`),
                                onQuotaExceeded: (errorCode) => {
                                    out.appendLine(`[Airlock Pipe] ⚠ Quota exceeded event: ${errorCode}`);
                                    updateSignInStatusBar(signInStatusBarItem, {
                                        status: "quota-warning",
                                        workspacesUsed: -1, workspacesLimit: -1,
                                    });
                                    vscode.window.showWarningMessage(
                                        `Airlock: Plan quota exceeded (${errorCode}). Requests are being allowed (fail-open) but you may need to upgrade your plan.`
                                    );
                                },
                            });
                            try { await _pipeProxy.start(); } catch { /* non-fatal */ }
                            out.appendLine("[Airlock Pairing] Pipe proxy restarted after re-pairing.");
                        }

                        // Re-install hooks with the new routing token
                        // (hooks.json and .cmd file are regenerated with the token baked in)
                        if (strategy) {
                            out.appendLine("[Airlock Pairing] Reinstalling hooks with new routing token...");
                            await strategy.reinstallHooks();
                        }

                        // Ensure presence is connected (may not have been if endpoint was set after init)
                        await ensurePresenceConnected();
                        await autoMode.enable(getConfig());
                    },
                    deviceAuth?.token
                );
            } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : String(err);
                out.appendLine(`[Airlock Pairing] ✗ Failed: ${msg}`);
                vscode.window.showErrorMessage(`Airlock: Pairing failed — ${msg}`);
            }
        }),

    );

    // ── Command: Set Enforcer ID ───────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.setEnforcerId", async () => {
            const current = getOrCreateEnforcerId(context);

            const newId = await vscode.window.showInputBox({
                title: "Airlock: Set Enforcer ID",
                prompt: "Enter a custom enforcer ID for this instance",
                value: current,
                placeHolder: "enf-xxxxxxxx",
            });

            if (newId !== undefined && newId.trim()) {
                await context.workspaceState.update("airlock.enforcerId", newId.trim());
                vscode.window.showInformationMessage(`Airlock: Enforcer ID set to "${newId.trim()}"`);
                out.appendLine(`[Airlock] Enforcer ID changed to: ${newId.trim()}`);
            }
        })
    );

    // ── Command: Unpair ────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.unpair", async () => {
            const routingToken = getRoutingToken(context);
            if (!routingToken) {
                vscode.window.showInformationMessage("Airlock: Not currently paired.");
                return;
            }

            const confirm = await vscode.window.showWarningMessage(
                "Airlock: Unpair from Mobile Approver? This will clear the routing token and encryption keys.",
                { modal: true },
                "Unpair"
            );

            if (confirm !== "Unpair") { return; }

            // Notify gateway to revoke the pairing record (best-effort)
            if (endpoint?.url) {
                try {
                    const headers: Record<string, string> = { "Content-Type": "application/json" };
                    if (deviceAuth?.token) { headers["Authorization"] = `Bearer ${deviceAuth.token}`; }
                    const resp = await fetch(`${endpoint.url}/v1/pairing/revoke`, {
                        method: "POST",
                        headers,
                        body: JSON.stringify({ routingToken }),
                    });
                    out.appendLine(`[Airlock] Gateway revoke: ${resp.status}`);
                } catch (e) {
                    out.appendLine(`[Airlock] Gateway revoke failed (non-fatal): ${e}`);
                }
            }

            // Don't stop auto-mode — hooks keep detecting.
            // Without routing token, submissions will pause until re-paired.

            await clearRoutingToken(context);
            // Clear workspace-scoped encryption key
            await clearEncryptionKey(context);
            // Clear paired X25519 keys from secret storage
            await context.secrets.delete("airlock.x25519PrivateKey");
            await context.workspaceState.update("airlock.x25519PublicKey", undefined);
            await context.workspaceState.update("airlock.pairedKeyId", undefined);
            await context.workspaceState.update("airlock.pairedPublicKey", undefined);

            updatePairingStatusBar(context);
            out.appendLine("[Airlock] Unpaired successfully. Routing token and keys cleared. Auto-mode continues detecting.");
            vscode.window.showInformationMessage("Airlock: Unpaired successfully.");
        })
    );

    // ── Command: Login (Device Authorization) ───────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.login", async () => {
            if (!deviceAuth) { deviceAuth = new DeviceAuth(context.secrets); }
            const success = await deviceAuth.login();
            if (success) {
                updateSignInStatusBar(signInStatusBarItem, { status: "signed-in" });
                await checkAndUpdateQuota(signInStatusBarItem, out);
                _refreshTimer?.dispose();
                _refreshTimer = deviceAuth.startRefreshTimer();

                // Restart pipe proxy with current endpoint and auth
                if (endpoint) {
                    _pipeProxy?.stop();
                    _pipeProxy = null;
                    const pipeName = NamedPipeProxy.getPipeName(enforcerId);
                    _pipeProxy = new NamedPipeProxy({
                        enforcerId,
                        gatewayUrl: endpoint.url,
                        localSecret: LOCAL_SECRET,
                        auth: () => deviceAuth,
                        getEncryptionKey: () => getEncryptionKey(context),
                        log: (msg) => out.appendLine(`[Airlock Pipe] ${msg}`),
                        onQuotaExceeded: (errorCode) => {
                            out.appendLine(`[Airlock Pipe] ⚠ Quota exceeded event: ${errorCode}`);
                            updateSignInStatusBar(signInStatusBarItem, {
                                status: "quota-warning",
                                workspacesUsed: -1, workspacesLimit: -1,
                            });
                            vscode.window.showWarningMessage(
                                `Airlock: Plan quota exceeded (${errorCode}). Requests are being allowed (fail-open) but you may need to upgrade your plan.`
                            );
                        },
                    });
                    try { await _pipeProxy.start(); } catch { /* non-fatal */ }
                }

                if (presenceClient && endpoint) {
                    presenceClient.disconnect();
                    presenceClient.connect(endpoint.url, () => deviceAuth?.token, enforcerId);
                }
            }
        })
    );

    // ── Command: Logout ─────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.logout", async () => {
            if (deviceAuth) {
                await deviceAuth.logout();
                _refreshTimer?.dispose(); _refreshTimer = null;
                presenceClient?.disconnect();
                updateSignInStatusBar(signInStatusBarItem, { status: "not-signed-in" });
                vscode.window.showInformationMessage("Airlock: Signed out. Gate script will now fail open until you sign in again.");
            }
        })
    );

    // ── Command: Open Settings ──────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.openSettings", () => {
            vscode.commands.executeCommand("workbench.action.openSettings", "airlock");
        })
    );
}

/** Update the pairing status bar item based on whether a routing token exists. */
function updatePairingStatusBar(context: vscode.ExtensionContext): void {
    const token = getRoutingToken(context);
    if (token) {
        pairingStatusBarItem.text = "$(check) Paired";
        pairingStatusBarItem.tooltip = "Airlock: Paired with Mobile Approver";
        pairingStatusBarItem.command = undefined; // No action when paired
    } else {
        pairingStatusBarItem.text = "$(plug) Pair";
        pairingStatusBarItem.tooltip = "Airlock: Click to pair with Mobile Approver";
        pairingStatusBarItem.command = "airlock.startPairing";
    }
}

export function deactivate() {
    if (presenceClient) {
        presenceClient.dispose();
        presenceClient = null;
    }
    if (_quotaTimer) {
        clearInterval(_quotaTimer);
        _quotaTimer = null;
    }
}

async function checkAndUpdateQuota(
    _item: vscode.StatusBarItem,
    _out: vscode.OutputChannel
): Promise<void> {
    // Periodic quota check via GET /v1/subscription/ through Gateway proxy.
    if (!deviceAuth?.isLoggedIn || !endpoint) { return; }
    try {
        const resp = await fetch(`${endpoint.url}/v1/subscription/`, {
            headers: { "Authorization": `Bearer ${deviceAuth.token}` },
        });
        if (!resp.ok) { _out.appendLine(`[Airlock Quota] Failed: ${resp.status}`); return; }
        const data = await resp.json() as {
            limits?: { maxWorkspaces?: number };
            resourceUsage?: { workspacesUsed?: number };
        };
        const maxWs = data.limits?.maxWorkspaces ?? -1;
        const usedWs = data.resourceUsage?.workspacesUsed ?? 0;
        if (maxWs >= 0 && usedWs > maxWs) {
            updateSignInStatusBar(_item, { status: "quota-warning", workspacesUsed: usedWs, workspacesLimit: maxWs });
            _out.appendLine(`[Airlock Quota] ⚠ Workspace limit exceeded: ${usedWs}/${maxWs}`);
        } else {
            updateSignInStatusBar(_item, { status: "signed-in" });
        }
    } catch (e) { _out.appendLine(`[Airlock Quota] Error: ${e}`); }
}

function startQuotaTimer(item: vscode.StatusBarItem, out: vscode.OutputChannel): { dispose(): void } {
    if (_quotaTimer) { clearInterval(_quotaTimer); }
    _quotaTimer = setInterval(() => { checkAndUpdateQuota(item, out); }, 5 * 60 * 1000);
    return { dispose: () => { if (_quotaTimer) { clearInterval(_quotaTimer); _quotaTimer = null; } } };
}
