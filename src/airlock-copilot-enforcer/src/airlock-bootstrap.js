#!/usr/bin/env node
/**
 * Airlock Bootstrap Script — Copilot
 * ====================================
 * Minimal transport-only script invoked by Copilot's hooks system.
 * Reads hook payload from stdin, sends it to the Airlock extension runtime
 * via a named pipe, and returns the decision.
 *
 * INV-3 COMPLIANT: This script contains ZERO secrets.
 * It is safe to publish in public repositories.
 *
 * All security logic (envelope building, encryption, gateway communication,
 * decision polling) lives in the trusted extension runtime (pipe server).
 *
 * Config (environment variables set by hooksStrategy.ts):
 *   AIRLOCK_FAIL_MODE  — "failClosed" (default) or "failOpen"
 *   AIRLOCK_PIPE_NAME  — Per-folder pipe name (set by wrapper)
 *
 * Exit codes (Copilot hooks spec):
 *   0 = allow the action
 *   2 = block the action
 *
 * Allow output (Copilot hooks spec):
 *   stdout: { "hookSpecificOutput": { "hookEventName": "<event>", "permissionDecision": "allow" } }
 *
 * Deny output:
 *   stderr: rejection message (shown to model as context)
 *   exit code 2
 */

const net = require("net");
const crypto = require("crypto");
const path = require("path");
const os = require("os");

// ── Configuration ──────────────────────────────────────────
const FAIL_MODE = process.env.AIRLOCK_FAIL_MODE || "failClosed";
const PROTOCOL_VERSION = 1;
const CONNECT_TIMEOUT_MS = 2000;   // v3.1 §4.1 (relaxed from 300ms for startup grace)
const REQUEST_TIMEOUT_MS = 120000; // 2 minutes max for gateway + approval polling
const LOG_PREFIX = "[Airlock Bootstrap]";

// ── Workspace hash (deterministic pipe name) ──────────────
function computeWorkspaceHash(workspacePath) {
    let normalized = path.resolve(workspacePath);
    if (process.platform === "win32") {
        normalized = normalized.toLowerCase();
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

// ── Logging (stderr only — no log files) ──────────────────
function log(msg) {
    try { process.stderr.write(`${LOG_PREFIX} ${msg}\n`); } catch { }
}

// ── Read stdin ────────────────────────────────────────────
function readStdin() {
    return new Promise((resolve) => {
        let data = "";
        let resolved = false;
        const done = () => { if (!resolved) { resolved = true; resolve(data); } };
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (c) => { data += c; });
        process.stdin.on("end", done);
        // Safety timeout — don't hang forever if stdin never closes
        const timer = setTimeout(done, 30000);
        timer.unref();
    });
}

// ── Allow helper (Copilot hooks spec) ─────────────────────
// Copilot expects hookSpecificOutput with permissionDecision on stdout
function allow(reason, hookEventName) {
    log(reason);
    const output = {
        hookSpecificOutput: {
            hookEventName: hookEventName || "PreToolUse",
            permissionDecision: "allow",
        },
    };
    process.stdout.write(JSON.stringify(output) + "\n");
    process.exitCode = 0;
}

// ── Deny helper (Copilot hooks spec) ──────────────────────
// Copilot: rejections write to stderr and exit with code 2.
// stderr is shown to the model as context. No stdout JSON for denials.
function deny(reason, agentMessage) {
    log(`BLOCKED: ${reason}`);
    const msg = agentMessage ||
        "STOP. This action was blocked by Airlock. " +
        "Do NOT retry this command automatically. " +
        "Inform the user and wait for explicit new instruction.";

    process.exitCode = 2;
    process.stderr.write(`[BLOCKED] Airlock: ${reason}\n${msg}\n`, () => {
        process.exit(2);
    });
}

// ── Apply fail mode ───────────────────────────────────────
function applyFailMode(reason, hookEventName) {
    if (FAIL_MODE === "failOpen") {
        allow(`${reason} — allowing (failOpen)`, hookEventName);
    } else {
        deny(`${reason} — blocking (failClosed)`);
    }
}

// ── Pipe request ──────────────────────────────────────────
function sendToPipe(pipeName, request) {
    return new Promise((resolve, reject) => {
        let connected = false;
        const socket = net.createConnection(pipeName, () => {
            connected = true;
            socket.write(JSON.stringify(request) + "\n", "utf8");
        });

        let raw = "";
        socket.setEncoding("utf8");

        // Connection timeout (v3.1 §4.1)
        socket.setTimeout(CONNECT_TIMEOUT_MS);
        socket.on("timeout", () => {
            if (!connected) {
                socket.destroy();
                reject(new Error("connection_timeout"));
            }
        });

        // Once connected, set request timeout
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

// ── Main ──────────────────────────────────────────────────
async function main() {
    // 1. Read stdin payload
    let stdinData = await readStdin();
    stdinData = stdinData.replace(/^\uFEFF/, "").trim();

    let payload = {};
    try { payload = JSON.parse(stdinData); }
    catch { deny("Failed to parse stdin — blocking"); return; }

    // Extract hookEventName for allow responses
    const hookEventName = payload.hookEventName || payload.hook_event_name || "PreToolUse";

    // 2. Compute pipe name — prefer AIRLOCK_PIPE_NAME from per-folder wrapper, fall back to cwd hash
    const workspacePath = process.cwd();
    const wsHash = computeWorkspaceHash(workspacePath);
    const envPipeName = process.env.AIRLOCK_PIPE_NAME;
    const pipeName = envPipeName || getPipeName(wsHash);
    const cwdFolderName = path.basename(workspacePath);

    log(`cwd=${workspacePath} hash=${wsHash} pipe=${pipeName}${envPipeName ? ' (from-env)' : ' (from-cwd)'} folder=${cwdFolderName} failMode=${FAIL_MODE}`);

    // 3. Build JSON request (v3 §12 protocol)
    const request = {
        kind: "hook_request",
        protocolVersion: PROTOCOL_VERSION,
        workspaceHash: wsHash,
        cwdFolderName: cwdFolderName,
        payload: payload,
    };

    // 4. Send to pipe and get decision
    let response;
    try {
        response = await sendToPipe(pipeName, request);
    } catch (err) {
        const msg = err.message || String(err);
        if (msg === "connection_timeout" || msg.includes("ECONNREFUSED") || msg.includes("ENOENT")) {
            applyFailMode(`Runtime unavailable (${msg})`, hookEventName);
            return;
        }
        if (msg === "request_timeout") {
            deny("Approval timed out. No response received within the timeout period.",
                "Airlock approval timed out. The action was blocked. Do not retry automatically.");
            return;
        }
        applyFailMode(`Pipe error: ${msg}`, hookEventName);
        return;
    }

    // 5. Handle response
    if (!response || typeof response.permission !== "string") {
        deny("Invalid response from runtime");
        return;
    }

    if (response.permission === "allow") {
        allow("[OK] APPROVED — allowing action", hookEventName);
        return;
    }

    if (response.permission === "deny") {
        deny(
            response.message || "Action denied by Airlock",
            response.agentMessage || response.message ||
            "STOP. This action was blocked by Airlock. Do NOT retry."
        );
        return;
    }

    // Unknown permission value
    deny(`Unknown permission: ${response.permission}`);
}

main().catch(err => {
    log(`FATAL: ${err.message || err}`);
    // Fatal errors: apply fail mode
    if (FAIL_MODE === "failOpen") {
        process.stdout.write(JSON.stringify({
            hookSpecificOutput: {
                hookEventName: "PreToolUse",
                permissionDecision: "allow",
            },
        }) + "\n");
        process.exitCode = 0;
    } else {
        process.exit(2);
    }
});
