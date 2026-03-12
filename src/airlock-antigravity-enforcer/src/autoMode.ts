import * as vscode from "vscode";
import * as crypto from "crypto";
import type {
    DetectionStrategy,
    DetectionConfig,
    PendingApproval,
} from "./detectionStrategy.js";
import type { EndpointInfo } from "./endpointResolver.js";
import { requestApproval, withdrawExchange, QuotaExceededError } from "./approvalClient.js";
import {
    updateToggleStatusBar,
    updateApprovalStatusBar,
} from "./statusBar.js";

const MAX_CONSECUTIVE_ERRORS = 5;
const APPROVAL_TIMEOUT_MS = 600_000;  // 10 min — matches artifact expiry

/**
 * Auto-Mode controller: subscribes to a DetectionStrategy,
 * routes detections through Gateway for mobile approval,
 * then executes via the strategy on ALLOW.
 */
export class AutoModeController implements vscode.Disposable {
    private _enabled = false;
    private _consecutiveErrors = 0;
    private _processing = false;
    private _strategyDisposable: vscode.Disposable | null = null;
    private _strategy: DetectionStrategy | null = null;
    private _pendingAbort: AbortController | null = null;
    private _diagnosticMode = false;

    constructor(
        private readonly _out: vscode.OutputChannel,
        private readonly _toggleItem: vscode.StatusBarItem,
        private readonly _approvalItem: vscode.StatusBarItem,
        private readonly _context: vscode.ExtensionContext,
        private _getEndpoint: () => EndpointInfo | null,
        private _getAuthToken: () => string | undefined = () => undefined
    ) {
        this._enabled = this._context.workspaceState.get("airlock.autoMode", false);
    }

    /** Update diagnostic mode at runtime. */
    setDiagnosticMode(enabled: boolean): void {
        this._diagnosticMode = enabled;
    }

    get isEnabled(): boolean {
        return this._enabled;
    }

    get strategyName(): string {
        return this._strategy?.name ?? "none";
    }

    /**
     * Set the active detection strategy and start if already enabled.
     */
    async setStrategy(strategy: DetectionStrategy, config: DetectionConfig): Promise<void> {
        // Stop previous strategy
        if (this._strategyDisposable) {
            this._strategyDisposable.dispose();
        }
        if (this._strategy) {
            await this._strategy.stop();
        }

        this._strategy = strategy;

        // Subscribe to detection events
        const subs: vscode.Disposable[] = [];
        subs.push(strategy.onPendingDetected(
            (pending) => void this._handlePending(pending)
        ));

        // Subscribe to cancellation events (button disappeared = user acted manually)
        if (strategy.onPendingCancelled) {
            subs.push(strategy.onPendingCancelled(() => {
                if (this._processing && this._pendingAbort) {
                    this._out.appendLine(`[Airlock Auto] Button disappeared — aborting pending approval`);
                    this._pendingAbort.abort();
                }
            }));
        }
        this._strategyDisposable = vscode.Disposable.from(...subs);

        // If already enabled, start the new strategy
        if (this._enabled) {
            await strategy.start(config);
            updateToggleStatusBar(this._toggleItem, "on");
        }
    }

    async enable(config: DetectionConfig): Promise<void> {
        this._enabled = true;
        this._processing = false;  // Reset in case previous approval was stuck
        this._consecutiveErrors = 0;
        await this._context.workspaceState.update("airlock.autoMode", true);

        if (this._strategy) {
            // Always restart strategy to clear _seenButtons and re-detect existing buttons
            await this._strategy.start(config);
        }

        this._out.appendLine("[Airlock Auto] ✓ Auto-Mode ENABLED.");
        updateToggleStatusBar(this._toggleItem, "on");
        updateApprovalStatusBar(this._approvalItem, "idle");
        vscode.window.showInformationMessage("Airlock: Auto-Mode enabled.");
    }

    async disable(reason?: string): Promise<void> {
        this._enabled = false;
        // Abort any in-flight approval request
        if (this._pendingAbort) {
            this._pendingAbort.abort();
            this._pendingAbort = null;
        }
        // Fully stop the strategy
        if (this._strategy) {
            await this._strategy.stop();
        }
        await this._context.workspaceState.update("airlock.autoMode", false);

        const msg = reason
            ? `[Airlock Auto] ✗ Disabled (${reason}).`
            : "[Airlock Auto] ✗ Disabled.";
        this._out.appendLine(msg);
        updateToggleStatusBar(this._toggleItem, "off");
        updateApprovalStatusBar(this._approvalItem, "idle");
        vscode.window.showInformationMessage(
            `Airlock: Auto-Mode disabled.${reason ? ` Reason: ${reason}` : ""}`
        );
    }

    /**
     * Handle a detected pending approval:
     * 1. Check endpoint
     * 2. Request approval from Gateway
     * 3. On ALLOW → strategy.executeApproval()
     * 4. On DENY → skip
     */
    private async _handlePending(pending: PendingApproval): Promise<void> {
        if (this._diagnosticMode) {
            this._out.appendLine(`[Airlock Auto] ──────────────────────────────────────────`);
            this._out.appendLine(`[Airlock Auto] EVENT: ${pending.type} "${pending.buttonText}"`);
            this._out.appendLine(`[Airlock Auto]   strategy: ${this._strategy?.name ?? 'none'} | processing: ${this._processing} | enabled: ${this._enabled}`);
        }
        if (!this._enabled || this._processing) {
            if (this._diagnosticMode) {
                this._out.appendLine(`[Airlock Auto]   SKIPPED (${!this._enabled ? 'disabled' : 'already processing'})`);
            }
            return;
        }

        const endpoint = this._getEndpoint();
        if (!endpoint) {
            this._out.appendLine(`[Airlock Auto]   NO ENDPOINT — pausing`);
            updateApprovalStatusBar(this._approvalItem, "paused");
            return;
        }
        if (this._diagnosticMode) {
            this._out.appendLine(`[Airlock Auto]   endpoint: ${endpoint.url}`);
        }

        // Abort any previous in-flight approval (button changed = manual action)
        if (this._pendingAbort) {
            this._out.appendLine(`[Airlock Auto] Aborting previous pending approval (new event detected)`);
            this._pendingAbort.abort();
            this._pendingAbort = null;
        }

        this._processing = true;
        const abortController = new AbortController();
        this._pendingAbort = abortController;
        // Pre-generate requestId so we can withdraw on error/timeout
        const requestId = "req-" + crypto.randomUUID();
        const handleStartTime = Date.now();
        try {
            this._out.appendLine(
                `[Airlock Auto] 📤 Requesting approval (${requestId})`
            );
            if (this._diagnosticMode) {
                this._out.appendLine(
                    `[Airlock Auto]   type: ${pending.type} | commandText: ${(pending.commandText ?? pending.buttonText).substring(0, 150)}`
                );
            }
            updateApprovalStatusBar(this._approvalItem, "approving");

            const response = await requestApproval(
                endpoint.url,
                pending.type,
                pending.commandText ?? pending.buttonText,
                pending.buttonText,
                this._out,
                600,
                this._context,
                requestId,
                abortController.signal,
                this._getAuthToken(),
                this._diagnosticMode
            );

            this._consecutiveErrors = 0;
            const roundTripMs = Date.now() - handleStartTime;

            if (response.decision === "approve") {
                this._out.appendLine(`[Airlock Auto] ✅ APPROVED (${roundTripMs}ms) — executing click`);
                try {
                    if (this._strategy) {
                        await this._strategy.executeApproval(pending);
                        this._out.appendLine(`[Airlock Auto] ✓ Approval click executed successfully`);
                    }
                } catch (clickErr) {
                    // Button is gone → user took manual action. Withdraw the exchange.
                    this._out.appendLine(`[Airlock Auto] Button gone (manual action?) — withdrawing exchange ${requestId}`);
                    void withdrawExchange(endpoint.url, requestId, this._out, this._getAuthToken());
                    updateApprovalStatusBar(this._approvalItem, "withdrawn");
                    setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 5000);
                    return;
                }
                updateApprovalStatusBar(this._approvalItem, "allowed");
                // Auto-hide after 5 seconds
                setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 5000);
            } else {
                this._out.appendLine(`[Airlock Auto] ❌ REJECTED (${roundTripMs}ms)${response.reason ? ` — reason: ${response.reason}` : ''}`);
                try {
                    if (this._strategy) {
                        await this._strategy.executeRejection(pending);
                        this._out.appendLine(`[Airlock Auto] ✓ Rejection click executed successfully`);
                    }
                } catch (clickErr) {
                    this._out.appendLine(`[Airlock Auto] Reject button gone (manual action?) — withdrawing exchange ${requestId}`);
                    void withdrawExchange(endpoint.url, requestId, this._out, this._getAuthToken());
                    updateApprovalStatusBar(this._approvalItem, "withdrawn");
                    setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 5000);
                    return;
                }
                updateApprovalStatusBar(this._approvalItem, "denied");
                vscode.window.showWarningMessage(
                    `Airlock: "${pending.buttonText}" rejected by mobile approver.`
                );
                // Auto-hide after 8 seconds
                setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 8000);
            }
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);

            // Quota exceeded → fail OPEN (auto-approve to not block developer)
            if (err instanceof QuotaExceededError) {
                this._out.appendLine(`[Airlock Auto] ⚠ Quota exceeded (${err.errorCode}) — allowing action (fail open, plan limit only)`);
                try {
                    if (this._strategy) {
                        await this._strategy.executeApproval(pending);
                        this._out.appendLine(`[Airlock Auto] ✓ Quota fail-open: approval click executed`);
                    }
                } catch { /* button gone */ }
                updateApprovalStatusBar(this._approvalItem, "allowed");
                setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 5000);
                return;
            }

            const isAbort = msg.includes("Aborted") || msg.includes("aborted");

            if (isAbort) {
                this._out.appendLine(`[Airlock Auto] ⏹ Approval ABORTED (manual action detected) — withdrawing ${requestId}`);
                void withdrawExchange(endpoint.url, requestId, this._out, this._getAuthToken());
                updateApprovalStatusBar(this._approvalItem, "withdrawn");
                setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 5000);
                return; // Don't count as error
            }

            this._consecutiveErrors++;
            this._out.appendLine(
                `[Airlock Auto] Error (${this._consecutiveErrors}/${MAX_CONSECUTIVE_ERRORS}): ${msg}`
            );
            // Timeout or network error — withdraw to clean up inbox
            this._out.appendLine(`[Airlock Auto] Withdrawing exchange ${requestId} due to error`);
            void withdrawExchange(endpoint.url, requestId, this._out, this._getAuthToken());

            updateApprovalStatusBar(this._approvalItem, "error");
            // Auto-hide after 5 seconds
            setTimeout(() => updateApprovalStatusBar(this._approvalItem, "idle"), 5000);

            if (this._consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                await this.disable(
                    `${MAX_CONSECUTIVE_ERRORS} consecutive errors — check endpoint`
                );
            }
        } finally {
            this._processing = false;
            this._pendingAbort = null;
        }
    }

    dispose(): void {
        if (this._strategyDisposable) {
            this._strategyDisposable.dispose();
        }
        if (this._strategy) {
            void this._strategy.stop();
        }
    }
}
