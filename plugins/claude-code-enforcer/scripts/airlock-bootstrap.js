#!/usr/bin/env node
/**
 * Airlock Bootstrap Script — Claude Code
 * ========================================
 * Minimal transport-only script invoked by Claude Code's PreToolUse hooks.
 * Reads Claude Code hook payload from stdin, normalizes it for the Airlock
 * pipe protocol, sends to the daemon/extension via named pipe, and returns
 * the decision in Claude Code's hook output format.
 *
 * This script does not make any HTTP requests. It only talks to the local daemon via a
 * named pipe; the daemon is the only process that communicates with the Airlock gateway.
 *
 * INV-3 COMPLIANT: This script contains ZERO secrets.
 * Safe to publish in public repositories.
 *
 * Config (environment):
 *   AIRLOCK_FAIL_MODE  — "failClosed" (default) or "failOpen"
 *   AIRLOCK_PIPE_NAME  — optional override for pipe/socket path
 *
 * Exit codes:
 *   0 = allow the action
 *   2 = block the action
 *
 * Claude Code PreToolUse: stdout may include hookSpecificOutput with
 * permissionDecision (allow|deny|ask) and permissionDecisionReason.
 */

const net = require("net");
const crypto = require("crypto");
const path = require("path");
const { spawn } = require("child_process");

// ── Configuration ──────────────────────────────────────────
let FAIL_MODE = "failClosed"; // Will be set from config or env
const PROTOCOL_VERSION = 1;
const CONNECT_TIMEOUT_MS = 2000;
const REQUEST_TIMEOUT_MS = 120000;
const LOG_PREFIX = "[Airlock Bootstrap]";

function computeWorkspaceHash(workspacePath) {
    let normalized = path.resolve(workspacePath);
    if (process.platform === "win32") {
        normalized = normalized.toLowerCase().replace(/\\/g, "/");
    }
    const digest = crypto.createHash("sha256").update(normalized).digest("hex");
    return digest.substring(0, 16);
}

function getPipeName(hash) {
    if (process.platform === "win32") {
        return `\\\\.\\pipe\\airlock-ws-${hash}`;
    }
    return `/tmp/airlock-ws-${hash}.sock`;
}

function log(msg) {
    try { process.stderr.write(`${LOG_PREFIX} ${msg}\n`); } catch { }
}

function readStdin() {
    return new Promise((resolve) => {
        let data = "";
        let resolved = false;
        const done = () => { if (!resolved) { resolved = true; resolve(data); } };
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (c) => { data += c; });
        process.stdin.on("end", done);
        const timer = setTimeout(done, 30000);
        timer.unref();
    });
}

/**
 * Returns true if the request is for this plugin's own auth/setup commands
 * (login, sign-in, pair, status) or tool use that is part of that flow (e.g. Glob
 * to find the plugin). Those must always be allowed so sign-in is possible
 * without a running daemon — avoiding the chicken-and-egg where the hook
 * would block the sign-in command itself.
 */
function isAirlockSelfCommand(payload) {
    const payloadStr = JSON.stringify(payload);
    const toolName = payload.tool_name || payload.toolName;

    // 1) Skill/command identifier — airlock:<command> (e.g. sign-in, sign-out, dev-mode, prod-mode, pair, unpair, status)
    const selfSkillPatterns = [
        "airlock:sign-in",
        "airlock:sign-out",
        "airlock:dev-mode",
        "airlock:prod-mode",
        "airlock:pair",
        "airlock:unpair",
        "airlock:status",
        "airlock:auto-on",
        "airlock:auto-off",
        "airlock:fail-mode",
        "airlock:approve",
        "airlock:disapprove",
        "airlock:patterns",
        "airlock-enforcer:sign-in",
        "airlock-enforcer:sign-out",
        "airlock-enforcer:dev-mode",
        "airlock-enforcer:prod-mode",
        "airlock-enforcer:pair",
        "airlock-enforcer:unpair",
        "airlock-enforcer:status",
        "airlock-enforcer:auto-on",
        "airlock-enforcer:auto-off",
        "airlock-enforcer:fail-mode",
        "airlock-enforcer:approve",
        "airlock-enforcer:disapprove",
        "airlock-enforcer:patterns",
    ];
    if (selfSkillPatterns.some((p) => payloadStr.includes(p))) return true;

    // 2) Bash: run-airlock.js/cli.js with known commands, or env-var-based airlock commands
    const toolInput = payload.tool_input || payload.input;
    if (toolName === "Bash" && toolInput) {
        const cmd = typeof toolInput.command === "string" ? toolInput.command : "";
        if (/echo\s+["']?CLAUDE_PLUGIN_ROOT/i.test(cmd)) return true;
        // Direct script or shim invocation (with or without env var prefixes)
        const selfScriptRe = /(?:run-airlock\.js|[/\\]daemon[/\\]cli\.js|airlock-enforcer(?:\.cmd)?)[\s\S]*?\b(login|sign-in|sign-out|dev-mode|prod-mode|logout|pair|unpair|status|auto-on|auto-off|fail-mode|approve|disapprove|patterns)\b/;
        if (selfScriptRe.test(cmd)) return true;
        // Any command that sets CLAUDE_PLUGIN_ROOT or AIRLOCK env vars and mentions airlock
        if (/(?:CLAUDE_PLUGIN_ROOT|AIRLOCK_PLUGIN_ROOT|AIRLOCK_WORKSPACE)/i.test(cmd) && /airlock/i.test(cmd)) return true;
        // Any command referencing the claude-code-enforcer plugin directory
        if (/claude-code-enforcer/i.test(cmd)) return true;
    }

    // 3) Glob used to find this plugin (any search mentioning airlock or the plugin)
    if (toolName === "Glob" && /(?:airlock|run-airlock|claude-code-enforcer)/i.test(payloadStr)) return true;

    // 4) Read (or Edit) of this plugin's own files — so the assistant can read the sign-in skill/command to run the script
    const filePath = (toolInput && (toolInput.file_path ?? toolInput.filePath)) || payload.file_path || payload.filePath || "";
    const pathStr = typeof filePath === "string" ? filePath : "";
    if (pathStr && (toolName === "Read" || toolName === "Edit")) {
        const pluginPathPattern = /(?:claude-code-enforcer|airlock-enforcer|plugin-root\.txt|run-airlock|airlock-sign-in|airlock-pair|airlock-status|airlock-sign-out|airlock-unpair|airlock-dev-mode|airlock-prod-mode|sign-in[/\\]SKILL|commands[/\\](?:airlock|sign-in|sign-out|dev-mode|prod-mode|pair|unpair|status|auto-on|auto-off|fail-mode|approve|disapprove|patterns)|skills[/\\]sign-in)/i;
        if (pluginPathPattern.test(pathStr)) return true;
    }

    // 5) ListDir / Bash ls/dir referencing the plugin directory
    if (toolName === "ListDir" && /(?:airlock|claude-code-enforcer)/i.test(payloadStr)) return true;

    return false;
}

/**
 * Normalize Claude Code PreToolUse payload so the pipe server (Cursor extension
 * or standalone daemon) sees the same shape it expects: event, command, cwd,
 * tool_name, tool_input, file_path.
 */
function normalizePayloadForPipe(payload) {
    const p = { ...payload };
    const toolName = p.tool_name || p.toolName;
    const toolInput = p.tool_input || p.input;

    if (toolName === "Bash" && toolInput && typeof toolInput.command === "string") {
        p.command = toolInput.command;
    }
    if (toolName === "Write" && toolInput && toolInput.file_path) {
        p.file_path = toolInput.file_path;
    }
    if (toolName === "Edit" && toolInput && toolInput.file_path) {
        p.file_path = toolInput.file_path;
    }
    if (toolName === "Read" && toolInput && toolInput.file_path) {
        p.file_path = toolInput.file_path;
    }
    // Map Claude Code PreToolUse to Cursor-style event names for pipe server
    if (String(toolName || "").startsWith("mcp__")) {
        p.event = "beforeMCPExecution";
    } else if (toolName === "Bash") {
        p.event = "beforeShellExecution";
    } else {
        p.event = p.hook_event_name || "PreToolUse";
    }
    return p;
}

/**
 * Extract command line text from a Bash tool use payload.
 * Returns null for non-Bash tool uses (they are not auto-approvable).
 */
function extractCommandLine(payload) {
    const toolName = payload.tool_name || payload.toolName;
    if (toolName !== "Bash") return null;
    const toolInput = payload.tool_input || payload.input;
    if (toolInput && typeof toolInput.command === "string") return toolInput.command;
    if (payload.command && typeof payload.command === "string") return payload.command;
    return null;
}

function allow(reason) {
    log(reason);
    const out = {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "allow",
            permissionDecisionReason: reason,
        },
    };
    process.stdout.write(JSON.stringify(out) + "\n");
    process.exitCode = 0;
}

function deny(reason, agentMessage) {
    log(`BLOCKED: ${reason}`);
    const msg = agentMessage ||
        "STOP. This action was blocked by Airlock. " +
        "Do NOT retry this command automatically. " +
        "Inform the user and wait for explicit new instruction.";
    const out = {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: msg,
        },
    };
    process.stderr.write(`[BLOCKED] Airlock: ${reason}\n`);
    process.stdout.write(JSON.stringify(out) + "\n");
    process.exit(0);
}

function applyFailMode(reason) {
    if (FAIL_MODE === "failOpen") {
        allow(`${reason} — allowing (failOpen)`);
    } else {
        deny(`${reason} — blocking (failClosed)`);
    }
}

function sendToPipe(pipeName, request) {
    return new Promise((resolve, reject) => {
        let connected = false;
        const socket = net.createConnection(pipeName, () => {
            connected = true;
            socket.write(JSON.stringify(request) + "\n", "utf8");
        });

        let raw = "";
        socket.setEncoding("utf8");
        socket.setTimeout(CONNECT_TIMEOUT_MS);
        socket.on("timeout", () => {
            if (!connected) {
                socket.destroy();
                reject(new Error("connection_timeout"));
            }
        });
        socket.on("connect", () => {
            socket.setTimeout(REQUEST_TIMEOUT_MS);
            socket.on("timeout", () => {
                socket.destroy();
                reject(new Error("request_timeout"));
            });
        });
        socket.on("data", (chunk) => { raw += chunk; });
        socket.on("end", () => {
            try {
                resolve(JSON.parse(raw));
            } catch {
                reject(new Error("invalid_response"));
            }
        });
        socket.on("error", reject);
    });
}

async function main() {
    // Load config for per-workspace settings
    let config = null;
    try {
        const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, "..");
        config = require(path.join(pluginRoot, "daemon", "config.js"));
        await config.loadCacheAsync();
    } catch {
        config = null;
    }

    let stdinData = await readStdin();
    stdinData = stdinData.replace(/^\uFEFF/, "").trim();

    let payload = {};
    try {
        payload = JSON.parse(stdinData);
    } catch {
        deny("Failed to parse stdin — blocking");
        return;
    }

    // Always allow this plugin's own auth/setup commands so sign-in works without a daemon
    if (isAirlockSelfCommand(payload)) {
        allow("Airlock plugin self-command (login/pair/status) — allowing");
        return;
    }

    // Read-only tools (Glob, Read, ListDir) are always safe — they can't modify anything.
    // Blocking them creates a chicken-and-egg where the assistant can't discover files.
    const toolName = payload.tool_name || payload.toolName;
    if (toolName === "Glob" || toolName === "Read" || toolName === "ListDir") {
        allow(`Read-only tool (${toolName}) — allowing`);
        return;
    }

    const workspacePath = payload.cwd || process.cwd();
    const wsHash = config ? config.findWorkspaceHash(workspacePath) : computeWorkspaceHash(workspacePath);

    // Resolve fail mode from per-workspace config (env var overrides inside getFailMode)
    if (config) {
        FAIL_MODE = config.getFailMode(wsHash);
    } else {
        FAIL_MODE = process.env.AIRLOCK_FAIL_MODE || "failClosed";
    }

    // Auto-mode check: if enforcement is disabled, allow everything
    if (config && !config.readAutoMode(wsHash)) {
        allow("Auto-mode OFF — allowing without checking daemon");
        return;
    }

    // If not paired, Airlock is effectively disabled — allow everything
    if (config) {
        const rt = config.getRoutingToken(wsHash);
        const ek = config.getEncryptionKey(wsHash);
        if (!rt || !ek) {
            allow("Not paired — Airlock disabled for this workspace");
            return;
        }
    }

    // Auto-approve pattern check (shell commands only, before pipe connection)
    const commandLine = extractCommandLine(payload);
    if (commandLine && config && config.isAutoApproved(wsHash, commandLine)) {
        allow(`AUTO-APPROVED: "${commandLine}" matches auto-approve pattern`);
        return;
    }

    const envPipeName = process.env.AIRLOCK_PIPE_NAME;
    const pipeName = envPipeName || getPipeName(wsHash);
    const cwdFolderName = path.basename(workspacePath);

    const normalizedPayload = normalizePayloadForPipe(payload);
    log(`cwd=${workspacePath} hash=${wsHash} pipe=${pipeName}${envPipeName ? " (from-env)" : " (from-cwd)"} folder=${cwdFolderName} failMode=${FAIL_MODE}`);

    const request = {
        kind: "hook_request",
        protocolVersion: PROTOCOL_VERSION,
        workspaceHash: wsHash,
        cwdFolderName: cwdFolderName,
        payload: normalizedPayload,
    };

    let response;
    try {
        response = await sendToPipe(pipeName, request);
    } catch (err) {
        const msg = err.message || String(err);
        if (msg === "connection_timeout" || msg.includes("ECONNREFUSED") || msg.includes("ENOENT")) {
            // Attempt to restart daemon if workspace is configured
            const restarted = await tryRestartDaemon(workspacePath);
            if (restarted) {
                try {
                    response = await sendToPipe(pipeName, request);
                } catch {
                    applyFailMode(`Runtime unavailable after restart attempt`);
                    return;
                }
            } else {
                applyFailMode(`Runtime unavailable (${msg})`);
                return;
            }
        } else if (msg === "request_timeout") {
            deny(
                "Approval timed out. No response received within the timeout period.",
                "Airlock approval timed out. The action was blocked. Do not retry automatically."
            );
            return;
        } else {
            applyFailMode(`Pipe error: ${msg}`);
            return;
        }
    }

    if (!response || typeof response.permission !== "string") {
        deny("Invalid response from runtime");
        return;
    }

    if (response.permission === "allow") {
        allow("[OK] APPROVED — allowing action");
        return;
    }

    if (response.permission === "deny") {
        deny(
            response.message || "Action denied by Airlock",
            response.agentMessage || response.message || "STOP. This action was blocked by Airlock. Do NOT retry."
        );
        return;
    }

    deny(`Unknown permission: ${response.permission}`);
}

/**
 * Try to restart the daemon process when the pipe is unavailable.
 * Returns true if daemon was successfully restarted and pipe is responsive.
 */
async function tryRestartDaemon(workspacePath) {
    try {
        const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.resolve(__dirname, "..");
        const daemonScript = path.join(pluginRoot, "daemon", "cli.js");
        log(`Attempting daemon restart: ${daemonScript} run`);
        // Pass grandparent PID so daemon can auto-shutdown when Claude TUI / VS Code exits
        const ppidArgs = process.ppid ? ["--ppid", String(process.ppid)] : [];
        const child = spawn(process.execPath, [daemonScript, "run", ...ppidArgs], {
            env: { ...process.env, AIRLOCK_WORKSPACE: workspacePath },
            detached: true,
            stdio: "ignore",
        });
        child.unref();
        // Wait for daemon to start
        await new Promise(r => setTimeout(r, 2000));
        return true;
    } catch (e) {
        log(`Daemon restart failed: ${e.message || e}`);
        return false;
    }
}

main().catch((err) => {
    log(`FATAL: ${err.message || err}`);
    if (FAIL_MODE === "failOpen") {
        process.stdout.write(
            JSON.stringify({
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: "allow",
                    permissionDecisionReason: "Fatal error — allowing (failOpen)",
                },
            }) + "\n"
        );
        process.exitCode = 0;
    } else {
        process.exit(2);
    }
});
