import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import type {
    DetectionStrategy,
    DetectionConfig,
    PendingApproval,
} from "./detectionStrategy.js";

const LOG_PREFIX = "[Airlock Hooks]";

/**
 * Hooks-based detection strategy for Windsurf IDE (v3 Architecture).
 *
 * Uses Windsurf's native hooks system to intercept agent actions
 * via `pre_run_command` and `pre_mcp_tool_use` events.
 *
 * Architecture (v3 §2):
 *   1. On start(), installs hooks.json pointing to bootstrap wrapper
 *   2. Bootstrap reads stdin, connects to named pipe, sends JSON hook_request
 *   3. Extension runtime (pipe server) handles all security logic
 *   4. Bootstrap exits 0 (allow) or 2 (deny) — no disk log files
 *
 * Since Windsurf's hooks system handles the blocking/allowing natively,
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
    private _hooksInstalled = false;

    constructor(
        private readonly _out: vscode.OutputChannel,
        private readonly _context: vscode.ExtensionContext,
        private readonly _enforcerId: string,
        private readonly _endpointUrl: string,
        private readonly _pipeName: string,
        private readonly _folderPath?: string,
    ) { }

    // ── Availability ───────────────────────────────────────────────

    async isAvailable(): Promise<boolean> {
        // This extension is Windsurf-only — hooks are always available
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
            this._log("✓ Hooks strategy started — Windsurf will gate actions through Airlock");
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`✗ Failed to install hooks: ${msg}`);
            throw err;
        }
    }

    async stop(): Promise<void> {
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

    /** Re-install hooks.json and bootstrap script with current config. */
    public async reinstallHooks(): Promise<void> {
        // Determine hooks.json location
        // If _folderPath is set (multi-root), use it. Otherwise fall back to first workspace folder.
        const folderPath = this._folderPath || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const hooksDir = folderPath
            ? path.join(folderPath, ".windsurf")
            : path.join(os.homedir(), ".windsurf");

        // Ensure .windsurf directory exists
        if (!fs.existsSync(hooksDir)) {
            fs.mkdirSync(hooksDir, { recursive: true });
            this._log(`Created hooks directory: ${hooksDir}`);
        }

        const hooksJsonPath = path.join(hooksDir, "hooks.json");

        // ── Clean up legacy files (v3 §18) ──────────────────────
        this._cleanupLegacyFiles(hooksDir);

        // ── Resolve bootstrap script path ─────────────────────────
        // Check out/ first (production), then src/ (F5 debug)
        let bootstrapScriptPath = path.join(__dirname, "airlock-bootstrap.js");
        if (!fs.existsSync(bootstrapScriptPath)) {
            const srcFallback = path.join(__dirname, "..", "src", "airlock-bootstrap.js");
            if (fs.existsSync(srcFallback)) {
                bootstrapScriptPath = srcFallback;
                this._log(`Bootstrap script resolved from src/ fallback: ${bootstrapScriptPath}`);
            } else {
                throw new Error(`Bootstrap script not found at ${bootstrapScriptPath} or ${srcFallback}`);
            }
        }

        // ── Build bootstrap wrapper ───────────────────────────────
        // The wrapper only passes AIRLOCK_FAIL_MODE and AIRLOCK_PIPE_NAME (not secrets).
        // Bootstrap computes the pipe name deterministically from cwd.
        const nodeCommand = "node";
        const failMode = vscode.workspace.getConfiguration("airlock")
            .get<string>("failMode", "failClosed");

        const isWindows = process.platform === "win32";
        let command: string;

        if (isWindows) {
            const cmdContent = [
                "@echo off",
                "setlocal",
                `set AIRLOCK_FAIL_MODE=${failMode}`,
                `set AIRLOCK_PIPE_NAME=${this._pipeName}`,
                `"${nodeCommand}" "${bootstrapScriptPath}"`,
                `exit /b %ERRORLEVEL%`,
            ].join("\r\n");

            const cmdPath = path.join(hooksDir, "airlock-bootstrap.cmd");
            safeWriteFile(cmdPath, cmdContent);
            this._log(`✓ Bootstrap wrapper: ${cmdPath} (read-only, zero secrets)`);
            command = cmdPath;
        } else {
            const escapeShell = (v: string) => v.replace(/'/g, "'\\''");
            const shContent = [
                "#!/bin/sh",
                `export AIRLOCK_FAIL_MODE='${escapeShell(failMode)}'`,
                `export AIRLOCK_PIPE_NAME='${escapeShell(this._pipeName)}'`,
                `exec '${escapeShell(nodeCommand)}' '${escapeShell(bootstrapScriptPath)}' "$@"`,
            ].join("\n");

            const shPath = path.join(hooksDir, "airlock-bootstrap.sh");
            // Remove read-only flag, write, set executable + read-only
            if (fs.existsSync(shPath)) {
                try { fs.chmodSync(shPath, 0o777); } catch { /* ignore */ }
            }
            fs.writeFileSync(shPath, shContent, { encoding: "utf8", mode: 0o555 });
            this._log(`✓ Bootstrap wrapper: ${shPath} (executable, read-only, zero secrets)`);
            command = shPath;
        }

        // ── Build hooks.json ──────────────────────────────────────
        // Windsurf expects: { hooks: { event_name: [{ command, show_output? }] } }
        const airlockHookEntry = { command: command, show_output: true };
        const cfg = vscode.workspace.getConfiguration("airlock");
        const enablePreWriteCode = cfg.get<boolean>("hookPreWriteCode", false);
        const enablePreReadCode = cfg.get<boolean>("hookPreReadCode", false);
        const enablePreUserPrompt = cfg.get<boolean>("hookPreUserPrompt", false);

        type HookEntry = { command: string; show_output?: boolean };
        const hooksConfig: Record<string, HookEntry[]> = {
            pre_run_command: [airlockHookEntry],
            pre_mcp_tool_use: [airlockHookEntry],
        };

        // Optional hooks — off by default
        if (enablePreWriteCode) {
            hooksConfig["pre_write_code"] = [airlockHookEntry];
        }
        if (enablePreReadCode) {
            hooksConfig["pre_read_code"] = [airlockHookEntry];
        }
        // pre_user_prompt: show_output is ignored by Windsurf for this hook
        if (enablePreUserPrompt) {
            hooksConfig["pre_user_prompt"] = [{ command: command }];
        }

        // ── Merge with existing hooks.json ────────────────────────
        type HooksObject = Record<string, Array<{ command?: string; show_output?: boolean }>>;
        let mergedHooks: HooksObject = { ...hooksConfig };

        if (fs.existsSync(hooksJsonPath)) {
            try {
                const parsed = JSON.parse(fs.readFileSync(hooksJsonPath, "utf8"));
                const existingHooks = parsed.hooks;

                if (existingHooks && typeof existingHooks === "object" && !Array.isArray(existingHooks)) {
                    for (const [eventName, entries] of Object.entries(existingHooks as HooksObject)) {
                        if (hooksConfig[eventName]) {
                            const nonAirlock = (entries ?? []).filter(
                                (h) => !h.command?.includes("airlock-bootstrap")
                                    && !h.command?.includes("hooksGateScript")
                                    && !h.command?.includes("airlock-gate")
                            );
                            mergedHooks[eventName] = [...nonAirlock, ...hooksConfig[eventName]];
                        } else {
                            const nonAirlock = (entries ?? []).filter(
                                (h) => !h.command?.includes("airlock-bootstrap")
                                    && !h.command?.includes("hooksGateScript")
                                    && !h.command?.includes("airlock-gate")
                            );
                            if (nonAirlock.length > 0) {
                                mergedHooks[eventName] = nonAirlock;
                            }
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

        const mergedConfig = { hooks: mergedHooks };

        // Write hooks.json (read-only)
        safeWriteFile(hooksJsonPath, JSON.stringify(mergedConfig, null, 2));
        const installedEvents = Object.keys(mergedHooks).filter(k => hooksConfig[k]).join(", ");
        this._log(`✓ Hooks installed at ${hooksJsonPath} (read-only)`);
        this._log(`  Events: ${installedEvents}`);
        this._log(`  FolderPath: ${folderPath}`);
        this._log(`  PipeName: ${this._pipeName} (bootstrap will compute from cwd)`);
        this._log(`  FailMode: ${failMode}`);

        // Install Windsurf project rule
        this._installWindsurfRule(hooksDir);

        vscode.window.showInformationMessage(
            `Airlock: Hooks installed at ${hooksJsonPath}. Agent actions will be gated through mobile approval.`
        );
    }

    /**
     * Writes .windsurf/rules/airlock.md — a Windsurf project rule that instructs
     * the agent to always allow airlock-bootstrap hook commands and never reject them.
     */
    private _installWindsurfRule(hooksDir: string): void {
        try {
            const rulesDir = path.join(hooksDir, "rules");
            if (!fs.existsSync(rulesDir)) {
                fs.mkdirSync(rulesDir, { recursive: true });
            }

            const rulePath = path.join(rulesDir, "airlock.md");

            const ruleContent = [
                "---",
                "description: Airlock mobile approval gateway hook",
                "alwaysApply: true",
                "---",
                "",
                "# Airlock Hook — Required Behavior",
                "",
                "This project uses the **Airlock** security gateway. A hook script (`airlock-bootstrap`) ",
                "runs before every shell command and MCP tool call to route it for mobile approval.",
                "",
                "## Rules",
                "",
                "- The `airlock-bootstrap` hook is a **trusted security component** installed by the Airlock Windsurf extension.",
                "- Do **not** attempt to skip, bypass, remove, or modify the `airlock-bootstrap` hook or `hooks.json`.",
                "- Do **not** reject, kill, or work around the hook process.",
                "- When a shell command is blocked by exit code 2 from the hook, respect the denial and do not retry the command automatically.",
                "- When a shell command is allowed (exit code 0 from the hook), proceed normally.",
                "- The hook communicates with a mobile app for human-in-the-loop approval — wait for it to complete (up to the configured timeout).",
                "- Never modify `.windsurf/hooks.json`, `.windsurf/airlock-bootstrap.cmd`, or `.windsurf/airlock-bootstrap.sh`.",
            ].join("\n");

            // Write as read-only to prevent agent tampering
            safeWriteFile(rulePath, ruleContent);

            this._log(`✓ Windsurf rule installed at ${rulePath} (read-only)`);
        } catch (err) {
            // Non-fatal — hooks still work, rule is just advisory
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`! Failed to install Windsurf rule: ${msg} (non-fatal)`);
        }
    }

    /** Clean up legacy pre-v3 files from .windsurf/ (v3 §18). */
    private _cleanupLegacyFiles(hooksDir: string): void {
        const legacyFiles = [
            "airlock-gate.cmd",
            "airlock-gate.sh",
            "hooksGateScript.js",
            "airlock-hooks.log",
        ];
        for (const file of legacyFiles) {
            const filePath = path.join(hooksDir, file);
            if (fs.existsSync(filePath)) {
                try {
                    // Remove read-only flag first
                    try { fs.chmodSync(filePath, 0o666); } catch { /* ignore */ }
                    fs.unlinkSync(filePath);
                    this._log(`✓ Cleaned up legacy file: ${file}`);
                } catch { /* non-fatal */ }
            }
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
        // Optionally clean up hooks.json on deactivation
        // (We leave them installed so they persist between sessions)
        this._onPendingDetected.dispose();
        this._onPendingCancelled.dispose();
    }
}

/** Safely write a file that may already be read-only, then set it read-only. */
function safeWriteFile(filePath: string, content: string): void {
    // Remove read-only flag if file exists (so we can overwrite)
    if (fs.existsSync(filePath)) {
        try { fs.chmodSync(filePath, 0o666); } catch { /* ignore */ }
    }
    fs.writeFileSync(filePath, content, "utf8");
    // Set read-only to prevent agent tampering
    try { fs.chmodSync(filePath, 0o444); } catch { /* ignore */ }
}
