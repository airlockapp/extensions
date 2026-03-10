import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
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

/** Per-folder Airlock context.
 *  For Windsurf, only the primary folder gets a pipe + hooks.
 *  Non-primary folders are tracked but have no pipe or hooks. */
interface WorkspaceContext {
    folderPath: string;
    folderName: string;
    proxy?: NamedPipeProxy;
    strategy?: HooksDetectionStrategy;
}

let endpoint: EndpointInfo | null = null;
let pairingStatusBarItem: vscode.StatusBarItem;
let presenceClient: PresenceClient | null = null;
let deviceAuth: DeviceAuth;
const _workspaceContexts = new Map<string, WorkspaceContext>();
let _refreshTimer: { dispose(): void } | null = null;
let _quotaTimer: ReturnType<typeof setInterval> | null = null;

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
    out.appendLine(`Airlock Windsurf Enforcer v3 activated. EnforcerId: ${enforcerId}`);
    out.show(true);

    // ── TLS configuration ─────────────────────────────────────
    const applyTlsConfig = () => {
        const allow = vscode.workspace.getConfiguration("airlock").get<boolean>("allowSelfSignedCerts", false);
        process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = allow ? "0" : "1";
        out.appendLine(`[Airlock] TLS: ${allow ? "self-signed certs allowed" : "strict TLS"}`);
    };
    applyTlsConfig();

    // Re-apply on setting change
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
            // Re-write bootstrap wrapper when config changes (failMode, auto-approve)
            if (e.affectsConfiguration("airlock.autoApprovePatterns") ||
                e.affectsConfiguration("airlock.failMode")) {
                out.appendLine("[Airlock] Config changed — updating workspace hooks and pipe server");
                const cfg = vscode.workspace.getConfiguration("airlock");
                for (const [, ctx] of _workspaceContexts) {
                    if (!ctx.proxy || !ctx.strategy) { continue; }
                    ctx.proxy.updateOptions({
                        autoApprovePatterns: cfg.get<string[]>("autoApprovePatterns", []),
                        failMode: cfg.get<string>("failMode", "failClosed") as "failClosed" | "failOpen",
                    });
                    ctx.strategy.reinstallHooks().catch(() => { /* non-fatal */ });
                }
            }
        })
    );

    // ── One-time migration: clear old globalState pairing data ──────
    const migrationKey = "airlock.migrated.workspaceState.v1";
    if (!context.globalState.get<boolean>(migrationKey)) {
        const oldKeys = ["airlock.routingToken", "airlock.pairedKeys",
            "airlock.x25519PublicKey", "airlock.pairedKeyId", "airlock.pairedPublicKey"];
        for (const key of oldKeys) {
            context.globalState.update(key, undefined);
        }
        context.secrets.delete("airlock.encryptionKey");
        context.secrets.delete("airlock.x25519PrivateKey");
        context.globalState.update(migrationKey, true);
        out.appendLine("[Airlock] ✓ Migrated: cleared old global pairing state.");
    }

    // ── Status Bar Items ─────────────────────────────────────────
    const toggleItem = createToggleStatusBarItem();
    context.subscriptions.push(toggleItem);

    const approvalItem = createApprovalStatusBarItem();
    context.subscriptions.push(approvalItem);

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

    // ── Diagnostic mode helper ─────────────────────────────────
    const logDiag = (msg: string) => {
        const diag = vscode.workspace.getConfiguration("airlock").get<boolean>("diagnosticMode", false);
        if (diag) {
            out.appendLine(`[Airlock Diag] ${msg}`);
        }
    };

    // ── Initialization ─────────────────────────────────────────

    /** Create a pipe server + hooks for a single workspace folder.
     *  For Windsurf, only the primary (first) folder gets a pipe + hooks.
     *  Non-primary folders are tracked but are inert. */
    const setupWorkspaceFolder = async (folder: vscode.WorkspaceFolder, isPrimary: boolean): Promise<WorkspaceContext | null> => {
        const folderPath = folder.uri.fsPath;
        const folderName = folder.name;

        // Skip if already set up
        if (_workspaceContexts.has(folderPath)) {
            return _workspaceContexts.get(folderPath)!;
        }

        const cfg = vscode.workspace.getConfiguration("airlock");
        const effectiveRepoName = vscode.workspace.name || folderName;

        // Non-primary folders: track but do not create pipe or hooks
        if (!isPrimary) {
            out.appendLine(`[Airlock] Folder ${folderName}: non-primary — skipping pipe & hooks`);
            const ctx: WorkspaceContext = { folderPath, folderName };
            _workspaceContexts.set(folderPath, ctx);
            return ctx;
        }

        // Primary folder: create pipe + hooks
        const workspaceHash = NamedPipeProxy.computeWorkspaceHash(folderPath);
        const pipeName = NamedPipeProxy.getPipeName(workspaceHash);

        out.appendLine(`[Airlock] Setting up primary folder: ${folderName} (repoName=${effectiveRepoName})`);
        logDiag(`hash=${workspaceHash}, pipe=${pipeName}`);

        // Create pipe server
        const proxy = new NamedPipeProxy({
            enforcerId,
            gatewayUrl: endpoint?.url ?? "",
            workspaceName: effectiveRepoName,
            repoName: effectiveRepoName,
            failMode: cfg.get<string>("failMode", "failClosed") as "failClosed" | "failOpen",
            autoApprovePatterns: cfg.get<string[]>("autoApprovePatterns", []),
            auth: () => deviceAuth,
            getEncryptionKey: () => getEncryptionKey(context),
            getRoutingToken: () => getRoutingToken(context),
            timeoutSeconds: cfg.get<number>("approvalTimeoutSeconds", 60),
            log: (msg) => out.appendLine(`[Airlock Pipe:${folderName}] ${msg}`),
            logDiag: (msg) => logDiag(`[Pipe:${folderName}] ${msg}`),
            onQuotaExceeded: (errorCode) => {
                out.appendLine(`[Airlock Pipe:${folderName}] ⚠ Quota exceeded: ${errorCode}`);
                updateSignInStatusBar(signInStatusBarItem, {
                    status: "quota-warning",
                    workspacesUsed: -1, workspacesLimit: -1,
                });
                vscode.window.showWarningMessage(
                    `Airlock: Plan quota exceeded (${errorCode}). You may need to upgrade your plan.`
                );
            },
        }, pipeName);

        try {
            await proxy.start();
        } catch (pipeErr) {
            out.appendLine(`[Airlock Pipe:${folderName}] Failed to start proxy: ${pipeErr}`);
        }

        // Create hooks strategy for this folder
        const strategy = new HooksDetectionStrategy(
            out,
            context,
            enforcerId,
            endpoint?.url ?? "",
            pipeName,
            folderPath,
        );

        const ctx: WorkspaceContext = { folderPath, folderName, proxy, strategy };
        _workspaceContexts.set(folderPath, ctx);
        context.subscriptions.push({ dispose: () => { proxy.stop(); } });
        context.subscriptions.push(strategy);

        return ctx;
    };

    /** Tear down a workspace folder's Airlock context. */
    const teardownWorkspaceFolder = (folderPath: string): void => {
        const ctx = _workspaceContexts.get(folderPath);
        if (!ctx) { return; }
        ctx.proxy?.stop();
        ctx.strategy?.dispose();
        _workspaceContexts.delete(folderPath);
        out.appendLine(`[Airlock] Removed folder context: ${ctx.folderName}`);
    };

    /** Ensure primary workspace folder has a pipe proxy running. */
    const ensureAllPipeProxies = async (): Promise<void> => {
        const folders = vscode.workspace.workspaceFolders || [];
        for (let i = 0; i < folders.length; i++) {
            await setupWorkspaceFolder(folders[i], i === 0);
        }
    };

    const init = async () => {
        endpoint = await resolveEndpoint(out, context.extension.packageJSON.name);

        // Set context key for command visibility (dev builds only show configureGateway)
        const isDevBuild = !context.extension.packageJSON.name || context.extension.packageJSON.name.endsWith("-dev");
        vscode.commands.executeCommand("setContext", "airlock.isDevBuild", isDevBuild);

        if (endpoint) {
            out.appendLine(`[Airlock] Gateway: ${endpoint.url} (${endpoint.source})`);
        } else {
            updateToggleStatusBar(toggleItem, "no-endpoint");
        }

        // ── Git safety warning (v3 §17) ─────────────────────────
        checkGitSafety(out);

        // ── Named Pipe Proxy (primary folder only, like Copilot) ─
        if (!deviceAuth) {
            deviceAuth = new DeviceAuth(context.secrets);
        }

        const folders = vscode.workspace.workspaceFolders || [];
        out.appendLine(`[Airlock] Workspace has ${folders.length} folder(s)`);
        out.appendLine(`[Airlock IDE] appName="${vscode.env.appName}" sessionId=${vscode.env.sessionId.substring(0, 8)}`);

        // Set up pipe + hooks for primary folder only; track non-primary folders
        let firstStrategy: HooksDetectionStrategy | null = null;
        for (let i = 0; i < folders.length; i++) {
            const ctx = await setupWorkspaceFolder(folders[i], i === 0);
            if (ctx?.strategy && !firstStrategy) {
                firstStrategy = ctx.strategy;
            }
        }

        // Use primary folder's strategy for auto-mode (Windsurf uses primary folder)
        if (firstStrategy) {
            await autoMode.setStrategy(firstStrategy, getConfig());
        }

        if (autoMode.isEnabled) {
            updateToggleStatusBar(toggleItem, "on");
        } else if (endpoint) {
            updateToggleStatusBar(toggleItem, "connected");
        }

        // ── Presence Client ────────────────────────────────────
        if (endpoint) {
            presenceClient = new PresenceClient(out, "3.0.0", "Windsurf");
            context.subscriptions.push({ dispose: () => presenceClient?.dispose() });

            presenceClient.onEvent(async (event) => {
                if (event === "connected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "disconnected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "pairing.revoked") {
                    out.appendLine("[Airlock] Pairing revoked by mobile approver.");
                    await clearRoutingToken(context);
                    await clearEncryptionKey(context);
                    await context.secrets.delete("airlock.x25519PrivateKey");
                    await context.workspaceState.update("airlock.x25519PublicKey", undefined);
                    await context.workspaceState.update("airlock.pairedKeyId", undefined);
                    await context.workspaceState.update("airlock.pairedPublicKey", undefined);
                    updatePairingStatusBar(context);
                    for (const [, ctx] of _workspaceContexts) {
                        try { if (ctx.strategy) { await ctx.strategy.reinstallHooks(); } } catch { /* non-fatal */ }
                    }
                    vscode.window.showWarningMessage(
                        "Airlock: The mobile approver removed this pairing. Hooks are now inactive — re-pair to resume enforcement."
                    );
                }
            });

            // Restore auth session and connect presence WS.
            deviceAuth = new DeviceAuth(context.secrets);
            const restored = await deviceAuth.restoreSession();

            if (restored) {
                await checkAndUpdateQuota(signInStatusBarItem, out);
                context.subscriptions.push(startQuotaTimer(signInStatusBarItem, out));
                _refreshTimer?.dispose();
                _refreshTimer = deviceAuth.startRefreshTimer();
                context.subscriptions.push({ dispose: () => { _refreshTimer?.dispose(); } });
                context.subscriptions.push(
                    deviceAuth.onAuthStateChanged((loggedIn) => {
                        if (loggedIn) {
                            updateSignInStatusBar(signInStatusBarItem, { status: "signed-in" });
                            checkAndUpdateQuota(signInStatusBarItem, out);
                            logDiag(`Token refreshed at ${new Date().toISOString()}`);
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

    // ── Listen for workspace folder changes (v3 §3-4) ──────────
    context.subscriptions.push(
        vscode.workspace.onDidChangeWorkspaceFolders(async (e) => {
            // Set up new folders
            for (const added of e.added) {
                out.appendLine(`[Airlock] Workspace folder added: ${added.name}`);
                const ctx = await setupWorkspaceFolder(added, false);
                if (ctx?.strategy) {
                    try { await ctx.strategy.start(getConfig()); } catch { /* non-fatal */ }
                }
            }
            // Tear down removed folders
            for (const removed of e.removed) {
                out.appendLine(`[Airlock] Workspace folder removed: ${removed.name}`);
                teardownWorkspaceFolder(removed.uri.fsPath);
            }
        })
    );

    // ── Helper: ensure presence connected ───────────────────────
    const ensurePresenceConnected = async () => {
        if (!endpoint) { return; }
        if (!deviceAuth) {
            deviceAuth = new DeviceAuth(context.secrets);
            await deviceAuth.restoreSession();
        }
        if (!presenceClient) {
            presenceClient = new PresenceClient(out, "3.0.0", "Windsurf");
            context.subscriptions.push({ dispose: () => presenceClient?.dispose() });
            presenceClient.onEvent(async (event) => {
                if (event === "connected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "disconnected") {
                    updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                } else if (event === "pairing.revoked") {
                    out.appendLine("[Airlock] Pairing revoked by mobile approver.");
                    await clearRoutingToken(context);
                    await clearEncryptionKey(context);
                    await context.secrets.delete("airlock.x25519PrivateKey");
                    await context.workspaceState.update("airlock.x25519PublicKey", undefined);
                    await context.workspaceState.update("airlock.pairedKeyId", undefined);
                    await context.workspaceState.update("airlock.pairedPublicKey", undefined);
                    updatePairingStatusBar(context);
                    for (const [, ctx] of _workspaceContexts) {
                        try { if (ctx.strategy) { await ctx.strategy.reinstallHooks(); } } catch { /* non-fatal */ }
                    }
                    vscode.window.showWarningMessage(
                        "Airlock: The mobile approver removed this pairing. Hooks are now inactive — re-pair to resume enforcement."
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
            'Airlock: No gateway configured. Use "Configure Gateway" to set one.'
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
            logDiag('requireAuth: already logged in');
            return true;
        }
        await deviceAuth.restoreSession();
        if (deviceAuth.isLoggedIn) {
            logDiag('requireAuth: session restored');
            return true;
        }
        out.appendLine('[Airlock] requireAuth: NOT logged in — prompting');
        const login = await vscode.window.showInformationMessage(
            'Airlock: You need to sign in before you can do this.',
            { modal: true, detail: 'Sign in to connect your extension to the Airlock Gateway.' },
            'Sign In'
        );
        if (login === 'Sign In') {
            return await deviceAuth.login(endpoint?.url);
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

            // Per-folder pipe info
            if (_workspaceContexts.size > 0) {
                out.appendLine(`Active Pipes: ${_workspaceContexts.size}`);
                for (const [, ctx] of _workspaceContexts) {
                    out.appendLine(`  - ${ctx.folderName}: ${ctx.proxy?.pipeName ?? '(no pipe)'}`);
                }
            } else {
                out.appendLine("Active Pipes: none");
            }

            const cfg = vscode.workspace.getConfiguration("airlock");
            out.appendLine(`Fail Mode: ${cfg.get<string>("failMode", "failClosed")}`);
            out.appendLine(`Diagnostic Mode: ${cfg.get<boolean>("diagnosticMode", false) ? "ON" : "OFF"}`);

            vscode.window.showInformationMessage(
                `Airlock: Endpoint=${epStr}, Strategy=${autoMode.strategyName}, Auto=${autoMode.isEnabled ? "ON" : "OFF"}, Pipes=${_workspaceContexts.size}`
            );
        })
    );

    // ── Command: Configure Gateway (dev builds only) ───────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.configureGateway", async () => {
            const current = endpoint?.url ?? "";
            const input = await vscode.window.showInputBox({
                title: "Airlock: Configure Gateway URL",
                prompt: "Enter the Airlock Gateway URL (e.g. http://localhost:5100)",
                value: current,
                placeHolder: "http://127.0.0.1:7771",
            });

            if (input === undefined) { return; }

            if (input.trim()) {
                await vscode.workspace.getConfiguration("airlock")
                    .update("gatewayUrl", input.trim(), vscode.ConfigurationTarget.Global);
                endpoint = { url: input.trim(), source: "setting" };
                updateToggleStatusBar(toggleItem, autoMode.isEnabled ? "on" : "connected");
                out.appendLine(`[Airlock] Gateway set: ${input.trim()}`);
                await ensurePresenceConnected();
            } else {
                await vscode.workspace.getConfiguration("airlock")
                    .update("gatewayUrl", undefined, vscode.ConfigurationTarget.Global);
                endpoint = await resolveEndpoint(out, context.extension.packageJSON.name);
                updateToggleStatusBar(toggleItem, endpoint ? "connected" : "no-endpoint");
            }
        })
    );


    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.startPairing", async () => {
            const url = requireEndpoint();
            if (!url) { return; }
            if (!await requireAuth()) { return; }

            const config = vscode.workspace.getConfiguration("airlock");
            const deviceId = config.get<string>("deviceId") || `dev-${Date.now()}`;

            try {
                const { generateX25519KeyPair, generateEncryptionKey } = await import("./crypto.js");
                const x25519KeyPair = generateX25519KeyPair();
                const encryptionKey = generateEncryptionKey();

                const enforcerLabel = "Windsurf";
                const workspaceName = vscode.workspace.name ?? vscode.workspace.workspaceFolders?.[0]?.name ?? "unknown";

                let token = deviceAuth?.token;
                let session: Awaited<ReturnType<typeof initiatePairing>>;
                try {
                    session = await initiatePairing(
                        url, deviceId, enforcerId, out,
                        x25519KeyPair.publicKey, enforcerLabel,
                        token, workspaceName
                    );
                } catch (initErr: unknown) {
                    const errMsg = initErr instanceof Error ? initErr.message : String(initErr);
                    if (errMsg.includes('401') && deviceAuth) {
                        out.appendLine('[Airlock Pairing] Got 401 — refreshing token and retrying...');
                        const refreshed = await deviceAuth.refresh();
                        if (refreshed) {
                            token = deviceAuth.token;
                            session = await initiatePairing(
                                url, deviceId, enforcerId, out,
                                x25519KeyPair.publicKey, enforcerLabel,
                                token, workspaceName
                            );
                        } else {
                            out.appendLine('[Airlock Pairing] Token refresh failed');
                            throw initErr;
                        }
                    } else {
                        throw initErr;
                    }
                }
                new PairingPanel(session, context, out, encryptionKey, x25519KeyPair, enforcerLabel, workspaceName,
                    async () => {
                        updatePairingStatusBar(context);
                        out.appendLine("[Airlock Pairing] ✓ Paired — updating pipe servers.");

                        // Ensure pipe proxies exist for all folders
                        await ensureAllPipeProxies();

                        // Re-install hooks for all folders
                        for (const [, ctx] of _workspaceContexts) {
                            if (!ctx.strategy) { continue; }
                            out.appendLine(`[Airlock Pairing] Reinstalling hooks for ${ctx.folderName}...`);
                            await ctx.strategy.reinstallHooks();
                        }

                        await ensurePresenceConnected();
                        await autoMode.enable(getConfig());

                        const choice = await vscode.window.showInformationMessage(
                            "Airlock: Pairing complete! Reload the window now to activate hooks in this session.",
                            { modal: false },
                            "Reload Window"
                        );
                        if (choice === "Reload Window") {
                            vscode.commands.executeCommand("workbench.action.reloadWindow");
                        }
                    },
                    token
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

            await clearRoutingToken(context);
            await clearEncryptionKey(context);
            await context.secrets.delete("airlock.x25519PrivateKey");
            await context.workspaceState.update("airlock.x25519PublicKey", undefined);
            await context.workspaceState.update("airlock.pairedKeyId", undefined);
            await context.workspaceState.update("airlock.pairedPublicKey", undefined);

            updatePairingStatusBar(context);
            out.appendLine("[Airlock] Unpaired successfully. Routing token and keys cleared.");
            vscode.window.showInformationMessage("Airlock: Unpaired successfully.");
        })
    );

    // ── Command: Login (Device Authorization) ───────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand("airlock.login", async () => {
            if (!deviceAuth) { deviceAuth = new DeviceAuth(context.secrets); }
            const success = await deviceAuth.login(endpoint?.url);
            if (success) {
                updateSignInStatusBar(signInStatusBarItem, { status: "signed-in" });
                await checkAndUpdateQuota(signInStatusBarItem, out);
                _refreshTimer?.dispose();
                _refreshTimer = deviceAuth.startRefreshTimer();

                // Update all workspace proxies with current auth
                for (const [, ctx] of _workspaceContexts) {
                    ctx.proxy?.updateOptions({
                        gatewayUrl: endpoint?.url ?? "",
                    });
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
                vscode.window.showInformationMessage("Airlock: Signed out. Hooks will now apply fail mode until you sign in again.");
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

/** Start a periodic quota check timer (every 5 minutes). */
function startQuotaTimer(
    item: vscode.StatusBarItem,
    out: vscode.OutputChannel
): { dispose(): void } {
    if (_quotaTimer) { clearInterval(_quotaTimer); }
    _quotaTimer = setInterval(() => {
        checkAndUpdateQuota(item, out);
    }, 5 * 60 * 1000);
    return { dispose: () => { if (_quotaTimer) { clearInterval(_quotaTimer); _quotaTimer = null; } } };
}

/** Check if .windsurf is tracked in git and warn (v3 §17). */
function checkGitSafety(out: vscode.OutputChannel): void {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) { return; }

    const gitignorePath = path.join(ws.uri.fsPath, ".gitignore");
    let isWindsurfIgnored = false;

    if (fs.existsSync(gitignorePath)) {
        try {
            const content = fs.readFileSync(gitignorePath, "utf8");
            const lines = content.split("\n").map(l => l.trim());
            isWindsurfIgnored = lines.some(l =>
                l === ".windsurf" || l === ".windsurf/" || l === ".windsurf/**" || l === "/.windsurf" || l === "/.windsurf/"
            );
        } catch { /* non-fatal */ }
    }

    if (!isWindsurfIgnored) {
        out.appendLine("[Airlock] ⚠ .windsurf/ not found in .gitignore — bootstrap scripts may be tracked in git.");
        vscode.window.showWarningMessage(
            "Airlock: The .windsurf/ directory is not in .gitignore. Consider adding it to prevent bootstrap scripts from being tracked.",
            "Add to .gitignore"
        ).then(choice => {
            if (choice === "Add to .gitignore") {
                try {
                    if (fs.existsSync(gitignorePath)) {
                        fs.appendFileSync(gitignorePath, "\n# Airlock bootstrap\n.windsurf/\n");
                    } else {
                        fs.writeFileSync(gitignorePath, "# Airlock bootstrap\n.windsurf/\n", "utf8");
                    }
                    out.appendLine("[Airlock] ✓ Added .windsurf/ to .gitignore");
                } catch { /* non-fatal */ }
            }
        });
    }
}
