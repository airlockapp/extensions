#!/usr/bin/env node
/**
 * Airlock Hooks Gate Script — Cursor
 * ======================================
 * Standalone Node.js script invoked by Cursor's hooks system.
 * Reads a JSON payload from stdin, submits it to the Airlock Gateway,
 * blocks waiting for the mobile approver's decision, and exits with:
 *   0 = allow the action
 *   2 = block the action (rejected by approver, or approval timeout)
 *
 * Security model — FAIL CLOSED throughout:
 *   JSON parse error, missing config, gateway errors  → exit 2 (block)
 *   Explicit rejection, approval timeout, fatal crash → exit 2 (block)
 *   Self-protection triggers                          → exit 2 (always)
 *   Only exit 0 on explicit APPROVED decision.
 *
 * Config comes from environment variables set by hooksStrategy.ts:
 *   AIRLOCK_PIPE_NAME       — Named pipe path (\\.\pipe\airlock-<id> or /tmp/airlock-*.sock)
 *   AIRLOCK_LOCAL_SECRET    — Per-session random secret for IPC authentication
 *   AIRLOCK_ENFORCER_ID     — Enforcer ID for this instance
 *   AIRLOCK_TIMEOUT_SECONDS — Max seconds to wait for decision (default 30)
 *   AIRLOCK_WORKSPACE_NAME  — Workspace name for metadata
 *   AIRLOCK_REPO_NAME       — Repository name for metadata
 *   AIRLOCK_LOG_FILE        — Optional log file path
 */

const net = require("net");
const crypto = require("crypto");
const fs = require("fs");

// ── Configuration ──────────────────────────────────────────
const PIPE_NAME = process.env.AIRLOCK_PIPE_NAME || "";
const LOCAL_SECRET = process.env.AIRLOCK_LOCAL_SECRET || "";
const ENFORCER_ID = process.env.AIRLOCK_ENFORCER_ID || "cursor-hooks";
const TIMEOUT_SECONDS = parseInt(process.env.AIRLOCK_TIMEOUT_SECONDS || "60", 10);
const WORKSPACE_NAME = process.env.AIRLOCK_WORKSPACE_NAME || "unknown";
const REPO_NAME = process.env.AIRLOCK_REPO_NAME || WORKSPACE_NAME;
const LOG_FILE = process.env.AIRLOCK_LOG_FILE || "";
const ROUTING_TOKEN = process.env.AIRLOCK_ROUTING_TOKEN || "";
const AUTO_APPROVE_RAW = process.env.AIRLOCK_AUTO_APPROVE || "";
const LOG_PREFIX = "[Airlock Hooks Gate]";

// ── Startup diagnostics ───────────────────────────────────────
const _startupDiag = [
    `PIPE_NAME=${PIPE_NAME ? "set (" + PIPE_NAME.substring(0, 30) + "...)" : "EMPTY"}`,
    `LOCAL_SECRET=${LOCAL_SECRET ? "set (" + LOCAL_SECRET.length + " chars)" : "EMPTY"}`,
    `ENFORCER_ID=${ENFORCER_ID}`,
    `WORKSPACE_NAME=${WORKSPACE_NAME}`,
    `ROUTING_TOKEN=${ROUTING_TOKEN ? "set (" + ROUTING_TOKEN.length + " chars)" : "EMPTY"}`,
    `TIMEOUT=${TIMEOUT_SECONDS}s`,
    `LOG_FILE=${LOG_FILE || "none"}`,
].join(" | ");


// ── Logging ───────────────────────────────────────────────────
function log(msg) {
    const line = `${LOG_PREFIX} ${msg}`;
    process.stderr.write(line + "\n");
    if (LOG_FILE) {
        try { fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${line}\n`); } catch { }
    }
}

// Diagnostic: log the actual exit code so we can confirm it in the output channel
process.on("exit", (code) => {
    const line = `${LOG_PREFIX} *** Process exiting with code ${code} ***`;
    try { process.stderr.write(line + "\n"); } catch { }
    if (LOG_FILE) {
        try { fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] ${line}\n`); } catch { }
    }
});

// ── Read stdin ────────────────────────────────────────────────
function readStdin() {
    return new Promise((resolve) => {
        let data = "";
        let resolved = false;
        const done = () => { if (!resolved) { resolved = true; resolve(data); } };
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", c => { data += c; });
        // Primary: resolve when the writing end closes stdin (normal case)
        process.stdin.on("end", done);
        // Safety: if stdin never closes (shouldn't happen), don't hang forever.
        // Use a long timeout — well beyond any expected payload delivery time.
        // IMPORTANT: .unref() so this timer doesn't keep the event loop alive
        // after main() returns with process.exitCode set.
        const stdinTimer = setTimeout(done, (TIMEOUT_SECONDS + 10) * 1000);
        stdinTimer.unref();
    });
}

// ── Named pipe request helper ────────────────────────────────
function pipeRequest(method, path, bodyStr) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(PIPE_NAME, () => {
            const headers = [
                `x-airlock-secret: ${LOCAL_SECRET}`,
                `x-airlock-method: ${method}`,
                `x-airlock-path: ${path}`,
            ].join("\n");
            socket.write(`${headers}\n\n${bodyStr || ""}`, "utf8");
        });

        let raw = "";
        socket.setEncoding("utf8");

        socket.on("data", (chunk) => { raw += chunk; });
        socket.on("end", () => {
            const idx = raw.indexOf("\n\n");
            const statusLine = idx >= 0 ? raw.slice(0, idx) : raw;
            const body = idx >= 0 ? raw.slice(idx + 2) : "";
            const match = statusLine.match(/^STATUS:\s*(\d+)/);
            const status = match ? parseInt(match[1], 10) : 500;
            try { resolve({ status, body: JSON.parse(body) }); }
            catch { resolve({ status, body }); }
        });

        socket.on("error", reject);
        socket.setTimeout((TIMEOUT_SECONDS + 15) * 1000, () => {
            socket.destroy();
            reject(new Error("pipe_timeout"));
        });
    });
}

// ── Deny helper (fail closed) ─────────────────────────────────
// Cursor hooks: exit code 2 blocks the action. We also write JSON to stdout
// with permission:"deny" + agentMessage for Cursor versions that check stdout.
// The rejection reason is also written to stderr for diagnostics.
function deny(reason, agentMessage) {
    log(`BLOCKED: ${reason}`);
    const msg = agentMessage ||
        "STOP. This action was blocked by Airlock. " +
        "Do NOT retry this command automatically. " +
        "Inform the user and wait for explicit new instruction.";

    // Write JSON deny to stdout (Cursor checks this for permission field)
    const denyResponse = JSON.stringify({
        permission: "deny",
        agentMessage: msg,
    });
    try { process.stdout.write(denyResponse + "\n"); } catch { /* ignore */ }

    // Safety: set exitCode first in case process.exit() doesn't propagate on Windows
    process.exitCode = 2;
    // Write rejection to stderr for diagnostics, then terminate with exit code 2.
    process.stderr.write(`[BLOCKED] Airlock REJECTED: ${reason}\n${msg}\n`, () => {
        process.exit(2);
    });
}

// ── Auto-approve pattern matching ─────────────────────────────
function isAutoApproved(commandText) {
    if (!AUTO_APPROVE_RAW) return false;
    const patterns = AUTO_APPROVE_RAW.split("|").filter(Boolean);
    if (patterns.length === 0) return false;
    const lower = commandText.toLowerCase();
    for (const pattern of patterns) {
        const p = pattern.trim();
        if (!p) continue;
        try {
            if (p.startsWith("/") && p.lastIndexOf("/") > 0) {
                const last = p.lastIndexOf("/");
                const re = new RegExp(p.substring(1, last), p.substring(last + 1) || "i");
                if (re.test(commandText)) return true;
            } else if (lower.includes(p.toLowerCase())) {
                return true;
            }
        } catch {
            if (lower.includes(p.toLowerCase())) return true;
        }
    }
    return false;
}

// ── Main ──────────────────────────────────────────────────────
async function main() {
    log(`Startup: ${_startupDiag}`);
    // 1. Parse stdin payload
    let stdinData = await readStdin();
    stdinData = stdinData.replace(/^\uFEFF/, "").trim();

    let payload = {};
    try { payload = JSON.parse(stdinData); }
    catch { deny("Failed to parse stdin — blocking (fail closed)"); return; }

    // 2. Use Cursor's hook_event_name as primary event source
    if (!payload.event && payload.hook_event_name) {
        payload.event = payload.hook_event_name;
    }

    // 3. Normalize Cursor-style field names
    if (!payload.toolName && payload.tool_name) { payload.toolName = payload.tool_name; }
    if (!payload.input && payload.tool_input) {
        // tool_input may be JSON string — parse if so
        if (typeof payload.tool_input === "string") {
            try { payload.input = JSON.parse(payload.tool_input); } catch { payload.input = payload.tool_input; }
        } else {
            payload.input = payload.tool_input;
        }
    }
    if (!payload.filePath && payload.file_path) { payload.filePath = payload.file_path; }

    // Infer event type from payload shape if hook_event_name is absent
    if (!payload.event) {
        if (payload.command !== undefined && payload.cwd !== undefined) { payload.event = "beforeShellExecution"; }
        else if (payload.serverName !== undefined || (payload.toolName && !payload.command)) { payload.event = "beforeMCPExecution"; }
        else if (payload.filePath !== undefined && !payload.edits) { payload.event = "beforeReadFile"; }
        else if (payload.filePath !== undefined && payload.edits !== undefined) { payload.event = "afterFileEdit"; }
        else { payload.event = "unknown"; }
    }

    // Canonical filePath from Cursor's file_path field or fallbacks
    const filePath = (payload.filePath || payload.file_path || payload.path || "").replace(/\\/g, "/").toLowerCase();
    const commandLine = payload.command || payload.toolName || "";
    log(`Event: ${payload.event} | Action: ${commandLine || filePath || "?"}`);

    // 5. Self-protection: block tampering with Airlock files
    // Now covers pre_read_code / pre_write_code via filePath extracted from tool_info.file_path above.
    const PROTECTED = ["hooks.json", "airlock-gate.cmd", "airlock-gate.sh", "hooksGateScript.js", "airlock-hooks.log"];
    const cmdLower = commandLine.toLowerCase();
    const toolInputStr = (typeof payload.input === "string" ? payload.input : JSON.stringify(payload.input || "")).toLowerCase();
    if (PROTECTED.some(p => filePath.includes(p.toLowerCase()) || cmdLower.includes(p.toLowerCase()) || toolInputStr.includes(p.toLowerCase()))) {
        deny("attempt to access protected Airlock file",
            "You cannot modify Airlock hooks configuration files (hooks.json, airlock-gate.cmd, etc). These files are protected.");
        return;
    }

    // 6. Validate config
    // Fail OPEN when not configured — blocking would prevent IDE use before sign-in.
    if (!PIPE_NAME) { log("AIRLOCK_PIPE_NAME not set — allowing (Airlock not configured)"); process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n"); process.exitCode = 0; return; }
    if (!LOCAL_SECRET) { log("AIRLOCK_LOCAL_SECRET not set — allowing (Airlock not configured)"); process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n"); process.exitCode = 0; return; }


    // 6b. Auto-approve patterns — skip Gateway for matching commands
    if (commandLine && isAutoApproved(commandLine)) {
        log(`AUTO-APPROVED: "${commandLine}" matches auto-approve pattern — skipping Gateway`);
        process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n");
        process.exitCode = 0;
        return;
    }

    // 7. Build and submit artifact envelope
    const requestId = "req-" + crypto.randomUUID();
    const msgId = "msg-" + crypto.randomUUID();
    const actionType = payload.event === "beforeShellExecution" ? "terminal_command" : "agent_step";

    const plaintextContent = JSON.stringify({
        actionType, commandText: commandLine,
        buttonText: buildDescription(payload),
        workspace: WORKSPACE_NAME, repoName: REPO_NAME,
        source: "cursor-hooks", hookEvent: payload.event,
        toolInput: payload.input ? JSON.stringify(payload.input).substring(0, 500) : undefined,
    });

    const envelope = {
        msgId, msgType: "artifact.submit", requestId,
        createdAt: new Date().toISOString(),
        sender: { enforcerId: ENFORCER_ID },
        body: {
            artifactType: "command-approval",
            artifactHash: crypto.createHash("sha256").update(`${actionType}:${commandLine}:${Date.now()}`).digest("hex"),
            ciphertext: { alg: "none", data: plaintextContent },
            expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
            metadata: Object.assign({ repoName: REPO_NAME, workspaceName: WORKSPACE_NAME }, ROUTING_TOKEN ? { routingToken: ROUTING_TOKEN } : {}),
        },
    };

    try {
        log(`Submitting via proxy pipe (requestId=${requestId})`);
        let submitResult;
        try {
            submitResult = await pipeRequest("POST", "/v1/artifacts", JSON.stringify(envelope));
        } catch (pipeErr) {
            log(`Pipe connection error: ${pipeErr.message || pipeErr} — allowing (fail open, pipe not available)`);
            process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n");
            process.exitCode = 0; return;
        }

        // 503 = not signed in — fail OPEN
        if (submitResult.status === 503) { log("Proxy returned 503 (not signed in) — allowing (fail open)"); process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n"); process.exitCode = 0; return; }
        // 401 = wrong secret — fail CLOSED
        if (submitResult.status === 401) { deny("Wrong local secret — security violation (fail closed)"); return; }
        // 403 = check error code to distinguish security vs quota errors
        if (submitResult.status === 403) {
            const errorCode = submitResult.body?.error || "";
            if (errorCode === "quota_exceeded" || errorCode === "workspace_limit_reached" || errorCode === "approver_limit_reached") {
                log(`Quota limit reached (${errorCode}) — allowing (fail open, plan limit only)`);
                process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n");
                process.exitCode = 0; return;
            }
            deny("Access denied — " + (errorCode || "pairing revoked") + " (fail closed)");
            return;
        }
        // 429 = approval quota exceeded — fail OPEN
        if (submitResult.status === 429) {
            log(`Quota exceeded (${submitResult.body?.error || "quota_exceeded"}) — allowing (fail open, plan limit only)`);
            process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n");
            process.exitCode = 0; return;
        }

        if (submitResult.status < 200 || submitResult.status >= 300) {
            deny(`Proxy/Gateway POST failed (${submitResult.status}) — blocking (fail closed)`);
            return;
        }
        log(`Artifact accepted (${submitResult.status}). Waiting for approval (timeout=${TIMEOUT_SECONDS}s)...`);
    } catch (err) {
        deny(`Gateway submit error: ${err.message || err} — blocking (fail closed)`);
        return;
    }

    // 8. Long-poll for decision (identical to approvalClient.ts)
    const pollIntervalSec = 25;
    const deadline = Date.now() + TIMEOUT_SECONDS * 1000;
    let pollCount = 0;

    while (Date.now() < deadline) {
        pollCount++;
        const remainingSec = Math.ceil((deadline - Date.now()) / 1000);
        const serverTimeout = Math.min(pollIntervalSec, remainingSec);
        if (serverTimeout <= 0) break;

        const waitPath = `/v1/exchanges/${requestId}/wait?timeout=${serverTimeout}`;
        log(`Poll ${pollCount}: waiting up to ${serverTimeout}s for decision...`);

        try {
            const waitResult = await pipeRequest("GET", waitPath, "");

            if (waitResult.status === 204 || !waitResult.body) {
                log(`Poll ${pollCount}: no decision yet, retrying...`);
                continue;
            }

            if (waitResult.status >= 200 && waitResult.status < 300 && waitResult.body) {
                // Unwrap envelope: { body: { decision: "..." } } or flat { decision: "..." }
                const outer = waitResult.body;
                const inner = outer.body || outer;
                const decision = (inner.decision || inner.Decision || inner.status || "").toLowerCase();

                log(`Poll ${pollCount}: decision="${decision}"`);

                if (decision === "approve" || decision === "approved") {
                    log("[OK] APPROVED — allowing action");
                    process.stdout.write(JSON.stringify({ permission: "allow" }) + "\n");
                    process.exitCode = 0;
                    return;
                }

                if (decision === "reject" || decision === "rejected") {
                    deny(
                        "Action REJECTED by Airlock mobile approver.",
                        "STOP. This action was explicitly REJECTED by the human approver via the Airlock mobile app. " +
                        "You MUST NOT retry this command, rephrase it, or attempt any equivalent action. " +
                        "Inform the user and wait for their explicit new instruction."
                    );
                    return;
                }

                log(`Poll ${pollCount}: unexpected decision="${decision}", retrying...`);
            }
        } catch (err) {
            log(`Poll ${pollCount} error: ${err.message || err}. Retrying...`);
            await new Promise(r => setTimeout(r, 1000));
        }
    }

    deny("Approval timed out. No response received within the timeout period.",
        "Airlock approval timed out. The action was blocked. Do not retry automatically.");
    return;
}

function buildDescription(payload) {
    const fp = payload.filePath || payload.file_path || payload.path || "(unknown)";
    switch (payload.event || "unknown") {
        case "beforeShellExecution":
            return `Terminal command: ${payload.command || "(unknown)"}${payload.cwd ? " (cwd: " + payload.cwd + ")" : ""}`;
        case "beforeMCPExecution":
            return `MCP: ${payload.serverName ? payload.serverName + "/" : ""}${payload.toolName || "(unknown)"}`;
        case "beforeReadFile":
            return `Read file: ${fp}`;
        case "afterFileEdit": {
            const editCount = Array.isArray(payload.edits) ? payload.edits.length : 0;
            return `Write file: ${fp}${editCount > 0 ? " (" + editCount + " edit" + (editCount > 1 ? "s" : "") + ")" : ""}`;
        }
        case "beforeSubmitPrompt":
            return `User prompt: ${(payload.prompt || "").substring(0, 200) || "(prompt)"}`;
        case "sessionStart":
            return `Session start`;
        case "subagentStart":
            return `Subagent start: ${payload.tool_name || payload.toolName || "(task)"}`;
        default:
            return `Hook event: ${payload.event || "unknown"}: ${payload.command || payload.toolName || fp || "?"}`;
    }
}

main().catch(err => {
    log(`FATAL: ${err.message || err} — blocking (fail closed)`);
    process.exit(2);
});
