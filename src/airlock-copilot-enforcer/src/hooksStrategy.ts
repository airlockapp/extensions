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
 * Legacy files to clean up on installation.
 * These are from the pre-v3 architecture where secrets were embedded
 * in wrapper scripts under .github/hooks/.
 */
const LEGACY_FILES = [
    "airlock-gate.cmd",
    "airlock-gate.sh",
    "airlock-hooks.log",
];

/**
 * Hooks-based detection strategy for GitHub Copilot (v3 Architecture).
 *
 * Uses the hooks system to intercept agent actions
 * via `PreToolUse` events (and optionally SessionStart, SubagentStart, etc.).
 *
 * v3 Architecture:
 *   1. On start(), installs airlock.json pointing to airlock-bootstrap
 *   2. Bootstrap is a minimal transport script (zero secrets, INV-3 compliant)
 *   3. Bootstrap connects to the named pipe server in the extension runtime
 *   4. All security logic runs in the trusted extension runtime
 *
 * Since the hooks system handles the blocking/allowing natively,
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
        // This extension is Copilot-only — hooks are always available
        this._log(`Running in ${vscode.env.appName} — hooks strategy available`);
        return true;
    }

    // ── Start / Stop ───────────────────────────────────────────────

    async start(config: DetectionConfig): Promise<void> {
        this._config = config;

        // Install airlock.json
        try {
            await this.reinstallHooks();
            this._hooksInstalled = true;
            this._log("✓ Hooks strategy started — Copilot will gate actions through Airlock");
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
    // Hooks handle this natively — the bootstrap exits with 0 or 2.
    // These methods are no-ops but required by the interface.

    async executeApproval(_pending: PendingApproval): Promise<void> {
        this._log("executeApproval called — hooks handle this natively via exit code 0");
    }

    async executeRejection(_pending: PendingApproval): Promise<void> {
        this._log("executeRejection called — hooks handle this natively via exit code 2");
    }

    // ── Hooks installation ─────────────────────────────────────────

    /** Re-install airlock.json and bootstrap script with current config. */
    public async reinstallHooks(): Promise<void> {
        // Determine airlock.json location
        // If _folderPath is set (multi-root), use it. Otherwise fall back to first workspace folder.
        const folderPath = this._folderPath || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        const hooksDir = folderPath
            ? path.join(folderPath, ".github", "hooks")
            : path.join(os.homedir(), ".github", "hooks");

        // Ensure .github/hooks directory exists
        if (!fs.existsSync(hooksDir)) {
            fs.mkdirSync(hooksDir, { recursive: true });
            this._log(`Created hooks directory: ${hooksDir}`);
        }

        const hooksJsonPath = path.join(hooksDir, "airlock.json");

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
        // The wrapper only passes AIRLOCK_FAIL_MODE + AIRLOCK_PIPE_NAME (not secrets).
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

        // ── Build airlock.json ────────────────────────────────────
        // VS Code Agent Hooks spec: { hooks: { EventName: [{ type: "command", command, timeout }] } }
        const airlockHookEntry = {
            type: "command" as const,
            command: command,
            timeout: this._getTimeoutSeconds(),
        };
        const cfg = vscode.workspace.getConfiguration("airlock");
        const enableSessionStart = cfg.get<boolean>("hookSessionStart", false);
        const enableUserPromptSubmit = cfg.get<boolean>("hookUserPromptSubmit", false);
        const enableSubagentStart = cfg.get<boolean>("hookSubagentStart", false);

        type HookEntry = { type: string; command: string; timeout?: number };
        const hooksConfig: Record<string, HookEntry[]> = {
            PreToolUse: [airlockHookEntry],
        };

        // Optional hooks — off by default
        if (enableSessionStart) {
            hooksConfig["SessionStart"] = [airlockHookEntry];
        }
        if (enableUserPromptSubmit) {
            hooksConfig["UserPromptSubmit"] = [airlockHookEntry];
        }
        if (enableSubagentStart) {
            hooksConfig["SubagentStart"] = [airlockHookEntry];
        }

        // ── Merge with existing airlock.json ──────────────────────
        type HooksObject = Record<string, HookEntry[]>;
        let mergedHooks: HooksObject = { ...hooksConfig };

        if (fs.existsSync(hooksJsonPath)) {
            try {
                const parsed = JSON.parse(fs.readFileSync(hooksJsonPath, "utf8"));
                const existingHooks = parsed.hooks;

                if (existingHooks && typeof existingHooks === "object" && !Array.isArray(existingHooks)) {
                    for (const [eventName, entries] of Object.entries(existingHooks as HooksObject)) {
                        if (hooksConfig[eventName]) {
                            // Event we manage — filter out old Airlock hooks, add ours
                            const nonAirlock = (entries ?? []).filter(
                                (h) => !h.command?.includes("airlock-bootstrap")
                                    && !h.command?.includes("hooksGateScript")
                                    && !h.command?.includes("airlock-gate")
                            );
                            mergedHooks[eventName] = [...nonAirlock, ...hooksConfig[eventName]];
                        } else {
                            // Event we don't manage — keep non-Airlock entries
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
                    this._log("Merged with existing airlock.json (object format)");
                } else {
                    this._log("Existing airlock.json has old/incompatible format — overwriting");
                }
            } catch {
                this._log("Existing airlock.json is invalid — overwriting");
            }
        }

        const mergedConfig = {
            hooks: mergedHooks,
        };

        // Write airlock.json (read-only)
        safeWriteFile(hooksJsonPath, JSON.stringify(mergedConfig, null, 2));
        const installedEvents = Object.keys(mergedHooks).filter(k => hooksConfig[k]).join(", ");
        this._log(`✓ Hooks installed at ${hooksJsonPath} (read-only)`);
        this._log(`  Events: ${installedEvents}`);
        this._log(`  FolderPath: ${folderPath}`);
        this._log(`  PipeName: ${this._pipeName} (bootstrap will compute from cwd)`);
        this._log(`  FailMode: ${failMode}`);

        // Install the Copilot project rule so the agent doesn't reject the hook
        // Rules go in .github/rules/ (Copilot's standard location)
        const githubDir = folderPath
            ? path.join(folderPath, ".github")
            : path.join(os.homedir(), ".github");
        this._installCopilotRule(githubDir);

        vscode.window.showInformationMessage(
            `Airlock: Hooks installed at ${hooksJsonPath}. Agent actions will be gated through mobile approval.`
        );
    }

    /**
     * Writes .github/rules/airlock.md — a project rule that instructs
     * the agent to always allow airlock-bootstrap hook commands and never reject them.
     */
    private _installCopilotRule(githubDir: string): void {
        try {
            const rulesDir = path.join(githubDir, "rules");
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
                "runs before every tool call to route it for mobile approval.",
                "",
                "## Rules",
                "",
                "- The `airlock-bootstrap` hook is a **trusted security component** installed by the Airlock Copilot extension.",
                "- Do **not** attempt to skip, bypass, remove, or modify the `airlock-bootstrap` hook or `airlock.json`.",
                "- Do **not** reject, kill, or work around the hook process.",
                "- When a tool call is blocked by exit code 2 from the hook, respect the denial and do not retry the action automatically.",
                "- When a tool call is allowed (exit code 0 from the hook), proceed normally.",
                "- The hook communicates with a mobile app for human-in-the-loop approval — wait for it to complete (up to the configured timeout).",
                "- Never modify `.github/hooks/airlock.json`, `.github/hooks/airlock-bootstrap.cmd`, or `.github/hooks/airlock-bootstrap.sh`.",
            ].join("\n");

            // Write as read-only
            if (fs.existsSync(rulePath)) {
                try { fs.chmodSync(rulePath, 0o666); } catch { /* ignore */ }
            }
            fs.writeFileSync(rulePath, ruleContent, "utf8");
            try { fs.chmodSync(rulePath, 0o444); } catch { /* ignore */ }

            this._log(`✓ Copilot rule installed at ${rulePath} (read-only)`);
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            this._log(`! Failed to install Copilot rule: ${msg} (non-fatal)`);
        }
    }

    /** Clean up legacy pre-v3 files from .github/hooks/ (v3 §18). */
    private _cleanupLegacyFiles(hooksDir: string): void {
        for (const file of LEGACY_FILES) {
            const filePath = path.join(hooksDir, file);
            if (fs.existsSync(filePath)) {
                try {
                    try { fs.chmodSync(filePath, 0o666); } catch { /* ignore */ }
                    fs.unlinkSync(filePath);
                    this._log(`✓ Deleted legacy file: ${filePath}`);
                } catch (err) {
                    const msg = err instanceof Error ? err.message : String(err);
                    this._log(`! Failed to delete legacy file ${filePath}: ${msg}`);
                }
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
        this._onPendingDetected.dispose();
        this._onPendingCancelled.dispose();
    }
}

/** Safely write a file that may already be read-only, then set it read-only. */
function safeWriteFile(filePath: string, content: string) {
    if (fs.existsSync(filePath)) {
        try { fs.chmodSync(filePath, 0o666); } catch { /* ignore */ }
    }
    fs.writeFileSync(filePath, content, "utf8");
    try { fs.chmodSync(filePath, 0o444); } catch { /* ignore */ }
}
