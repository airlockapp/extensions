import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import type {
    DetectionStrategy,
    DetectionConfig,
    PendingApproval,
} from "./detectionStrategy.js";
import { NamedPipeProxy } from "./namedPipeProxy.js";
import { getRoutingToken } from "./crypto.js";

const LOG_PREFIX = "[Airlock Hooks]";

/**
 * Hooks-based detection strategy for Cursor IDE.
 *
 * Uses Cursor's native hooks system (v1.7+ beta) to intercept agent actions
 * via `beforeShellExecution` and `preToolUse` events.
 *
 * Architecture:
 *   1. On start(), installs `hooks.json` pointing to `hooksGateScript.js`
 *   2. The gate script runs as a separate process invoked by Cursor
 *   3. Gate script calls Gateway → gets approval → exits with 0/2
 *   4. This strategy monitors a log file for reporting/diagnostics
 *
 * Since Cursor's hooks system handles the blocking/allowing natively,
 * this strategy doesn't need to detect buttons or click them.
 * The `onPendingDetected` event is fired for informational logging only.
 */
export class HooksDetectionStrategy implements DetectionStrategy {
    readonly name = "hooks";

    private readonly _onPendingDetected = new vscode.EventEmitter<PendingApproval>();
    readonly onPendingDetected = this._onPendingDetected.event;

    private readonly _onPendingCancelled = new vscode.EventEmitter<string>();
    readonly onPendingCancelled = this._onPendingCancelled.event;

    private _config: DetectionConfig | null = null;
    private _logWatcher: fs.FSWatcher | null = null;
    private _hooksInstalled = false;

    constructor(
        private readonly _out: vscode.OutputChannel,
        private readonly _context: vscode.ExtensionContext,
        private readonly _enforcerId: string,
        private readonly _endpointUrl: string,
        private readonly _pipeName: string,
        private readonly _localSecret: string,
    ) { }

    // ── Availability ───────────────────────────────────────────────

    async isAvailable(): Promise<boolean> {
        // This extension is Cursor-only — hooks are always available
        this._log(`Running in ${vscode.env.appName} — hooks strategy available`);
        return true;
    }

    // ── Start / Stop ───────────────────────────────────────────────

    async start(config: DetectionConfig): Promise<void> {
        this._config = config;

        // Install hooks.json
        try {
            await this.reinstallHooks();
            this._hooksInstalled = true;
            this._log("✓ Hooks strategy started — Cursor will gate actions through Airlock");
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`✗ Failed to install hooks: ${msg}`);
            throw err;
        }

        // Start monitoring the gate script's log file for diagnostics
        this._startLogMonitor();
    }

    async stop(): Promise<void> {
        if (this._logWatcher) {
            this._logWatcher.close();
            this._logWatcher = null;
        }
        this._log("Hooks strategy stopped");
    }

    // ── Execute approval/rejection ─────────────────────────────────
    // Hooks handle this natively — the gate script exits with 0 or 2.
    // These methods are no-ops but required by the interface.

    async executeApproval(_pending: PendingApproval): Promise<void> {
        this._log("executeApproval called — hooks handle this natively via exit code 0");
    }

    async executeRejection(_pending: PendingApproval): Promise<void> {
        this._log("executeRejection called — hooks handle this natively via exit code 2");
    }

    // ── Hooks installation ─────────────────────────────────────────

    /** Re-install hooks.json and gate script with current config (e.g., after pairing). */
    public async reinstallHooks(): Promise<void> {
        // Determine hooks.json location
        // Project-level: .cursor/hooks.json in workspace root
        // Global: ~/.cursor/hooks.json
        const ws = vscode.workspace.workspaceFolders?.[0];
        const hooksDir = ws
            ? path.join(ws.uri.fsPath, ".cursor")
            : path.join(os.homedir(), ".cursor");

        // Ensure .cursor directory exists
        if (!fs.existsSync(hooksDir)) {
            fs.mkdirSync(hooksDir, { recursive: true });
            this._log(`Created hooks directory: ${hooksDir}`);
        }

        const hooksJsonPath = path.join(hooksDir, "hooks.json");

        // Resolve gate script path (bundled with the extension)
        // Check out/ first (production), then src/ (F5 debug — copy step may not have run)
        let gateScriptPath = path.join(__dirname, "hooksGateScript.js");
        if (!fs.existsSync(gateScriptPath)) {
            const srcFallback = path.join(__dirname, "..", "src", "hooksGateScript.js");
            if (fs.existsSync(srcFallback)) {
                gateScriptPath = srcFallback;
                this._log(`Gate script resolved from src/ fallback: ${gateScriptPath}`);
            } else {
                throw new Error(`Gate script not found at ${gateScriptPath} or ${srcFallback}`);
            }
        }

        // Build the hooks config
        // NOTE: process.execPath returns Cursor.exe (Electron binary), not node.exe.
        // Cursor hooks run commands via shell, so we use 'node' from PATH.
        const nodeCommand = "node";

        // Get workspace and repo name for metadata
        const workspaceName = ws?.name ?? "unknown";
        const airlockCfg = vscode.workspace.getConfiguration("airlock");
        const autoApprovePatterns = (airlockCfg.get<string[]>("autoApprovePatterns", []) || []).join("|");

        // Log file for gate script diagnostics (in .cursor dir next to hooks.json)
        const logFilePath = path.join(hooksDir, "airlock-hooks.log");

        // On Windows, use a .cmd batch wrapper that sets env vars and runs node.
        // PowerShell doesn't properly forward stdin/piping when Cursor invokes hooks.
        const isWindows = process.platform === "win32";
        let command: string;

        if (isWindows) {
            const routingToken = getRoutingToken(this._context) || "";
            const cmdContent = [
                "@echo off",
                "setlocal",
                `set AIRLOCK_PIPE_NAME=${this._pipeName}`,
                `set AIRLOCK_LOCAL_SECRET=${this._localSecret}`,
                `set AIRLOCK_ENFORCER_ID=${this._enforcerId}`,
                `set AIRLOCK_TIMEOUT_SECONDS=${this._getTimeoutSeconds()}`,
                `set AIRLOCK_WORKSPACE_NAME=${workspaceName}`,
                `set AIRLOCK_REPO_NAME=`,
                `set AIRLOCK_LOG_FILE=${logFilePath}`,
                `set AIRLOCK_ROUTING_TOKEN=${routingToken}`,
                `set AIRLOCK_AUTO_APPROVE=${autoApprovePatterns}`,
                `"${nodeCommand}" "${gateScriptPath}"`,
                `exit /b %ERRORLEVEL%`,
            ].join("\r\n");

            const cmdPath = path.join(hooksDir, "airlock-gate.cmd");
            // Remove old read-only flag if it exists, write, then set read-only
            if (fs.existsSync(cmdPath)) {
                try { fs.chmodSync(cmdPath, 0o666); } catch { /* ignore */ }
            }
            fs.writeFileSync(cmdPath, cmdContent, "utf8");
            try { fs.chmodSync(cmdPath, 0o444); } catch { /* ignore */ }
            this._log(`Wrote gate batch wrapper: ${cmdPath} (read-only)`);

            command = cmdPath;
        } else {
            // Unix (Linux / macOS): create a .sh wrapper that exports env vars
            // and runs node. This avoids shell quoting issues that can occur when
            // workspace names or paths contain $, backticks, or double-quotes.
            const escapeShell = (v: string) => v.replace(/'/g, "'\\''");
            const routingTokenUnix = getRoutingToken(this._context) || "";
            const shContent = [
                "#!/bin/sh",
                `export AIRLOCK_PIPE_NAME='${escapeShell(this._pipeName)}'`,
                `export AIRLOCK_LOCAL_SECRET='${escapeShell(this._localSecret)}'`,
                `export AIRLOCK_ENFORCER_ID='${escapeShell(this._enforcerId)}'`,
                `export AIRLOCK_TIMEOUT_SECONDS='${this._getTimeoutSeconds()}'`,
                `export AIRLOCK_WORKSPACE_NAME='${escapeShell(workspaceName)}'`,
                `export AIRLOCK_REPO_NAME=''`,
                `export AIRLOCK_LOG_FILE='${escapeShell(logFilePath)}'`,
                `export AIRLOCK_ROUTING_TOKEN='${escapeShell(routingTokenUnix)}'`,
                `export AIRLOCK_AUTO_APPROVE='${escapeShell(autoApprovePatterns)}'`,
                `exec '${escapeShell(nodeCommand)}' '${escapeShell(gateScriptPath)}' "$@"`,
            ].join("\n");

            const shPath = path.join(hooksDir, "airlock-gate.sh");
            // Remove old read-only flag if it exists, write, then set read-only + executable
            if (fs.existsSync(shPath)) {
                try { fs.chmodSync(shPath, 0o777); } catch { /* ignore */ }
            }
            fs.writeFileSync(shPath, shContent, { encoding: "utf8", mode: 0o555 });
            this._log(`Wrote gate shell wrapper: ${shPath} (executable, read-only)`);

            command = shPath;
        }

        // Build hooks.json content (version 1 format per Cursor docs)
        // Cursor expects: hooks = { eventName: [{ command, matcher? }] }
        const airlockHookEntry = { command: command, matcher: ".*", timeout: this._getTimeoutSeconds() };
        const cfg = vscode.workspace.getConfiguration("airlock");
        const enableBeforeSubmitPrompt = cfg.get<boolean>("hookBeforeSubmitPrompt", false);
        const enableStop = cfg.get<boolean>("hookStop", false);
        const enableSessionStart = cfg.get<boolean>("hookSessionStart", false);
        const enableSubagentStart = cfg.get<boolean>("hookSubagentStart", false);
        const enableBeforeReadFile = cfg.get<boolean>("hookBeforeReadFile", false);

        const hooksConfig: Record<string, Array<{ command: string; matcher?: string }>> = {
            beforeShellExecution: [airlockHookEntry],
            beforeMCPExecution: [airlockHookEntry],
        };


        // Optional hooks — off by default
        if (enableBeforeSubmitPrompt) {
            hooksConfig["beforeSubmitPrompt"] = [airlockHookEntry];
        }
        if (enableStop) {
            hooksConfig["stop"] = [airlockHookEntry];
        }
        if (enableSessionStart) {
            hooksConfig["sessionStart"] = [airlockHookEntry];
        }
        if (enableSubagentStart) {
            hooksConfig["subagentStart"] = [airlockHookEntry];
        }
        if (enableBeforeReadFile) {
            hooksConfig["beforeReadFile"] = [airlockHookEntry];
        }

        // Read existing hooks.json — only merge if it has the correct object format
        type HooksObject = Record<string, Array<{ command?: string; matcher?: string }>>;
        let mergedHooks: HooksObject = { ...hooksConfig };

        if (fs.existsSync(hooksJsonPath)) {
            try {
                const parsed = JSON.parse(fs.readFileSync(hooksJsonPath, "utf8"));
                const existingHooks = parsed.hooks;

                // Only merge if hooks is a plain object (not an array from old format)
                if (existingHooks && typeof existingHooks === "object" && !Array.isArray(existingHooks)) {
                    // Merge: for each event, keep non-Airlock hooks and add ours
                    for (const [eventName, entries] of Object.entries(existingHooks as HooksObject)) {
                        if (hooksConfig[eventName]) {
                            // Event we manage — filter out old Airlock hooks, add ours
                            const nonAirlock = (entries ?? []).filter(
                                (h) => !h.command?.includes("hooksGateScript")
                                    && !h.command?.includes("airlock-gate")
                            );
                            mergedHooks[eventName] = [...nonAirlock, ...hooksConfig[eventName]];
                        } else {
                            // Event we don't manage — strip any stale Airlock hooks,
                            // keep only non-Airlock entries (e.g. user's own hooks).
                            const nonAirlock = (entries ?? []).filter(
                                (h) => !h.command?.includes("hooksGateScript")
                                    && !h.command?.includes("airlock-gate")
                            );
                            if (nonAirlock.length > 0) {
                                mergedHooks[eventName] = nonAirlock;
                            }
                            // If no non-Airlock hooks remain, omit the event entirely
                        }
                    }
                    this._log("Merged with existing hooks.json (object format)");
                } else {
                    this._log("Existing hooks.json has old array format — overwriting");
                }
            } catch {
                this._log("Existing hooks.json is invalid — overwriting");
            }
        }

        const mergedConfig = {
            version: 1,
            hooks: mergedHooks,
        };

        // Helper: safely write a file that may already be read-only
        const safeWriteFile = (filePath: string, content: string) => {
            // Remove read-only flag if file exists (so we can overwrite)
            if (fs.existsSync(filePath)) {
                try { fs.chmodSync(filePath, 0o666); } catch { /* ignore */ }
            }
            fs.writeFileSync(filePath, content, "utf8");
            // Set read-only to prevent agent tampering
            try { fs.chmodSync(filePath, 0o444); } catch { /* ignore */ }
        };

        // Write hooks.json (read-only to prevent agent tampering)
        safeWriteFile(hooksJsonPath, JSON.stringify(mergedConfig, null, 2));
        const installedEvents = Object.keys(mergedHooks).filter(k => hooksConfig[k]).join(", ");
        this._log(`✓ Hooks installed at ${hooksJsonPath} (read-only)`);
        this._log(`  Events: ${installedEvents}`);
        this._log(`  PipeName: ${this._pipeName}`);
        this._log(`  EnforcerId: ${this._enforcerId}`);
        this._log(`  LogFile: ${logFilePath}`);

        // Install the Cursor project rule so the agent doesn't reject the hook
        this._installCursorRule(hooksDir);

        // Show notification to the user
        vscode.window.showInformationMessage(
            `Airlock: Hooks installed at ${hooksJsonPath}. Agent actions will be gated through mobile approval.`
        );
    }

    /**
     * Writes .cursor/rules/airlock.mdc — a Cursor project rule that instructs
     * the agent to always allow airlock-gate hook commands and never reject them.
     *
     * Project rules with alwaysApply: true are injected into every agent context,
     * so the agent knows it must cooperate with the hook process rather than
     * declining or ignoring it.
     */
    private _installCursorRule(hooksDir: string): void {
        try {
            const rulesDir = path.join(hooksDir, "rules");
            if (!fs.existsSync(rulesDir)) {
                fs.mkdirSync(rulesDir, { recursive: true });
            }

            const rulePath = path.join(rulesDir, "airlock.mdc");

            const ruleContent = [
                "---",
                "description: Airlock mobile approval gateway hook",
                "alwaysApply: true",
                "---",
                "",
                "# Airlock Hook — Required Behavior",
                "",
                "This project uses the **Airlock** security gateway. A hook script (`airlock-gate`) ",
                "runs before every shell command and MCP tool call to route it for mobile approval.",
                "",
                "## Rules",
                "",
                "- The `airlock-gate` hook is a **trusted security component** installed by the Airlock VS Code extension.",
                "- Do **not** attempt to skip, bypass, remove, or modify the `airlock-gate` hook or `hooks.json`.",
                "- Do **not** reject, kill, or work around the hook process.",
                "- When a shell command is blocked by exit code 2 from the hook, respect the denial and do not retry the command automatically.",
                "- When a shell command is allowed (exit code 0 from the hook), proceed normally.",
                "- The hook communicates with a mobile app for human-in-the-loop approval — wait for it to complete (up to the configured timeout).",
                "- Never modify `.cursor/hooks.json`, `.cursor/airlock-gate.cmd`, or `.cursor/airlock-gate.sh`.",
            ].join("\n");

            // Write as read-only to prevent agent tampering
            if (fs.existsSync(rulePath)) {
                try { fs.chmodSync(rulePath, 0o666); } catch { /* ignore */ }
            }
            fs.writeFileSync(rulePath, ruleContent, "utf8");
            try { fs.chmodSync(rulePath, 0o444); } catch { /* ignore */ }

            this._log(`✓ Cursor rule installed at ${rulePath} (read-only)`);
        } catch (err) {
            // Non-fatal — hooks still work, rule is just advisory
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`! Failed to install Cursor rule: ${msg} (non-fatal)`);
        }
    }

    // ── Log monitoring ─────────────────────────────────────────────

    private _startLogMonitor(): void {
        // Monitor the gate script's log file and surface entries in our output channel
        const ws = vscode.workspace.workspaceFolders?.[0];
        const hooksDir = ws
            ? path.join(ws.uri.fsPath, ".cursor")
            : path.join(os.homedir(), ".cursor");
        const logFilePath = path.join(hooksDir, "airlock-hooks.log");

        // Clear any stale log from previous session
        try { fs.writeFileSync(logFilePath, "", "utf8"); } catch { /* ok */ }

        let lastSize = 0;
        const tailLog = () => {
            try {
                const stat = fs.statSync(logFilePath);
                if (stat.size > lastSize) {
                    const fd = fs.openSync(logFilePath, "r");
                    const buf = Buffer.alloc(stat.size - lastSize);
                    fs.readSync(fd, buf, 0, buf.length, lastSize);
                    fs.closeSync(fd);
                    lastSize = stat.size;

                    const lines = buf.toString("utf8").trim().split("\n");
                    for (const line of lines) {
                        this._out.appendLine(line.trim());
                    }
                }
            } catch { /* file may not exist yet */ }
        };

        // Use fs.watch for instant feedback, with fallback polling
        // Windows fs.watch fires multiple events per write — debounce to avoid duplicates
        try {
            let debounceTimer: ReturnType<typeof setTimeout> | undefined;
            this._logWatcher = fs.watch(logFilePath, () => {
                if (debounceTimer) { clearTimeout(debounceTimer); }
                debounceTimer = setTimeout(tailLog, 100);
            });
            this._log("Monitoring gate script log file for diagnostics");
        } catch {
            // File doesn't exist yet — poll periodically
            const interval = setInterval(tailLog, 2000);
            this._logWatcher = { close: () => clearInterval(interval) } as fs.FSWatcher;
            this._log("Polling gate script log file for diagnostics");
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private _getTimeoutSeconds(): number {
        return vscode.workspace
            .getConfiguration("airlock")
            .get<number>("approvalTimeoutSeconds", 60);
    }

    private _log(msg: string): void {
        this._out.appendLine(`${LOG_PREFIX} ${msg}`);
    }

    dispose(): void {
        if (this._logWatcher) {
            this._logWatcher.close();
            this._logWatcher = null;
        }

        // Optionally clean up hooks.json on deactivation
        // (We leave them installed so they persist between sessions)
        this._onPendingDetected.dispose();
        this._onPendingCancelled.dispose();
    }
}
