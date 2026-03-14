"use strict";

const net = require("net");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const auth = require("./auth.js");
const config = require("./config.js");
const gateway = require("./gateway.js");
const dndClient = require("./dndClient.js");
const { getEnforcerId } = require("./pairing.js");

let _enforcerId = null; // Set by startPipeServer from workspace path
let _wsHash = null;    // Set by startPipeServer from workspace path

const PROTOCOL_VERSION = 1;
const MAX_PAYLOAD_BYTES = 1024 * 1024;
const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

let lastActivityAt = Date.now();
let currentRequestId = null; // Track in-flight exchange for withdrawal on shutdown
let _shutdownCallback = null; // Set by startPipeServer for clean shutdown

function getPipeName(workspaceHash) {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\airlock-ws-${workspaceHash}`;
  }
  return `/tmp/airlock-ws-${workspaceHash}.sock`;
}

function normalizePayload(payload) {
  const p = { ...payload };
  if (!p.event && p.hook_event_name) p.event = p.hook_event_name;
  if (!p.toolName && p.tool_name) p.toolName = p.tool_name;
  if (!p.input && p.tool_input) {
    p.input = typeof p.tool_input === "string" ? (() => { try { return JSON.parse(p.tool_input); } catch { return p.tool_input; } })() : p.tool_input;
  }
  if (!p.filePath && p.file_path) p.filePath = p.file_path;
  if (!p.event) {
    if (p.command !== undefined && p.cwd !== undefined) p.event = "beforeShellExecution";
    else if (String(p.toolName || "").startsWith("mcp__")) p.event = "beforeMCPExecution";
    else p.event = "unknown";
  }
  return p;
}

function buildDescription(payload) {
  const event = (payload.event || "unknown").toString();
  const cmd = payload.command || payload.toolName || "";
  const fp = payload.file_path || payload.filePath || payload.path || "(unknown)";
  if (event === "beforeShellExecution") return `Terminal: ${cmd}${payload.cwd ? " (cwd: " + payload.cwd + ")" : ""}`;
  if (event === "beforeMCPExecution") return `MCP: ${payload.toolName || "(unknown)"}`;
  if (event === "PreToolUse" && payload.tool_name === "Bash" && payload.tool_input && payload.tool_input.command) {
    return `Terminal: ${payload.tool_input.command}`;
  }
  if (payload.tool_name === "Write" || payload.tool_name === "Edit") return `Write: ${fp}`;
  if (payload.tool_name === "Read") return `Read: ${fp}`;
  return cmd || fp || event;
}

function applyFailMode(socket, reason, log) {
  const failMode = config.getFailMode(_wsHash);
  if (failMode === "failOpen") {
    log(`Fail-open: ${reason}`);
    sendResponse(socket, { permission: "allow" });
  } else {
    log(`Fail-closed: ${reason}`);
    sendResponse(socket, {
      permission: "deny",
      message: reason,
      agentMessage: "Airlock daemon unavailable or not configured. Start daemon and sign in (login + pair).",
    });
  }
}

function sendResponse(socket, obj) {
  try {
    socket.write(JSON.stringify(obj) + "\n", "utf8");
    socket.end();
  } catch (e) {
    socket.destroy();
  }
}

function handleConnection(socket, log) {
  lastActivityAt = Date.now();
  let rawData = "";
  let totalBytes = 0;
  socket.setEncoding("utf8");

  socket.on("data", (chunk) => {
    totalBytes += Buffer.byteLength(chunk, "utf8");
    if (totalBytes > MAX_PAYLOAD_BYTES) {
      sendResponse(socket, { permission: "deny", message: "Payload too large" });
      return;
    }
    rawData += chunk;
    const nlIdx = rawData.indexOf("\n");
    if (nlIdx >= 0) {
      const jsonStr = rawData.substring(0, nlIdx);
      processRequest(socket, jsonStr, log).catch((err) => {
        log(`Request error: ${err.message}`);
        sendResponse(socket, { permission: "deny", message: "Internal error" });
      });
    }
  });

  socket.on("error", () => {});
}

async function processRequest(socket, raw, log) {
  let request;
  try {
    request = JSON.parse(raw);
  } catch {
    sendResponse(socket, { permission: "deny", message: "Invalid JSON" });
    return;
  }

  if (request.kind === "shutdown") {
    log("Shutdown requested via pipe");
    // Withdraw any in-flight exchange
    if (currentRequestId) {
      const creds = config.readCredentials();
      const token = await auth.ensureFreshToken();
      if (creds && creds.gatewayUrl && token) {
        gateway.withdrawExchange(creds.gatewayUrl, currentRequestId, token, log).catch(() => {});
      }
    }
    sendResponse(socket, { status: "ok" });
    if (_shutdownCallback) _shutdownCallback();
    setTimeout(() => process.exit(0), 500);
    return;
  }

  if (request.kind !== "hook_request") {
    sendResponse(socket, { permission: "deny", message: "Unknown request kind" });
    return;
  }
  if (request.protocolVersion !== PROTOCOL_VERSION) {
    sendResponse(socket, { permission: "deny", message: "Incompatible protocol version" });
    return;
  }

  const payload = request.payload || {};
  const normalized = normalizePayload(payload);
  const commandLine =
    normalized.command ||
    (normalized.tool_name === "Bash" && normalized.tool_input && normalized.tool_input.command
      ? normalized.tool_input.command
      : "") ||
    normalized.toolName ||
    "";
  const effectiveRepoName = request.cwdFolderName || (payload.cwd ? path.basename(payload.cwd) : "workspace");
  const workspaceName = effectiveRepoName;

  const actionType =
    normalized.event === "beforeShellExecution" ? "terminal_command" : "agent_step";
  const buttonText = buildDescription(normalized);

  const token = await auth.ensureFreshToken();
  if (!token) {
    applyFailMode(socket, "Not signed in", log);
    return;
  }
  if (!config.getRoutingToken(_wsHash)) {
    applyFailMode(socket, "Not paired", log);
    return;
  }

  // Auto-mode check: if enforcement is disabled, allow everything
  if (!config.readAutoMode(_wsHash)) {
    log("Auto-mode OFF — allowing without gateway");
    sendResponse(socket, { permission: "allow" });
    return;
  }

  // Auto-approve pattern check (shell commands only)
  if (commandLine && config.isAutoApproved(_wsHash, commandLine)) {
    log(`AUTO-APPROVED: "${commandLine}" matches auto-approve pattern`);
    sendResponse(socket, { permission: "allow" });
    return;
  }

  const creds = config.readCredentials();
  if (!creds || !creds.gatewayUrl) {
    applyFailMode(socket, "No gateway URL (run login first)", log);
    return;
  }

  // DND policy evaluation — check before submitting artifact
  try {
    const dndResult = await dndClient.evaluateDndForAction(
      {
        endpointUrl: creds.gatewayUrl,
        workspaceId: workspaceName,
        enforcerId: _enforcerId,
        authToken: token,
      },
      { actionType, commandText: commandLine || buttonText },
      log
    );
    if (dndResult) {
      log(`DND policy ${dndResult.policyId}: ${dndResult.decision} (${dndResult.scope})`);
      if (dndResult.decision === "approve") {
        sendResponse(socket, { permission: "allow", message: `DND: auto-approved (${dndResult.scope})` });
        return;
      }
      if (dndResult.decision === "reject") {
        sendResponse(socket, {
          permission: "deny",
          message: `DND: auto-denied (${dndResult.scope})`,
          agentMessage: "Action blocked by Do Not Disturb policy.",
        });
        return;
      }
    }
  } catch (e) {
    log(`DND evaluation error (non-fatal): ${e.message || e}`);
  }

  // Track in-flight request for withdrawal on shutdown
  const requestId = "req-" + crypto.randomUUID();
  currentRequestId = requestId;

  const result = await gateway.requestApproval(
    {
      gatewayUrl: creds.gatewayUrl,
      actionType,
      commandText: commandLine || buttonText,
      buttonText,
      workspaceName,
      repoName: effectiveRepoName,
      enforcerId: _enforcerId,
      wsHash: _wsHash,
      timeoutSeconds: 120,
    },
    log
  );

  currentRequestId = null;

  if (!result.permission) result.permission = "deny";
  sendResponse(socket, {
    permission: result.permission,
    message: result.message,
    agentMessage: result.agentMessage,
  });
}

function startPipeServer(workspacePath, log, onShutdown) {
  const hash = config.computeWorkspaceHash(workspacePath);
  const pipeName = getPipeName(hash);
  _enforcerId = getEnforcerId(workspacePath);
  _wsHash = hash;
  _shutdownCallback = onShutdown || null;

  const server = net.createServer((socket) => handleConnection(socket, log));

  // Inactivity timeout — safety net for daemon cleanup
  const inactivityTimer = setInterval(() => {
    if (Date.now() - lastActivityAt > INACTIVITY_TIMEOUT_MS) {
      log("No pipe activity for 5 min — shutting down daemon");
      if (_shutdownCallback) _shutdownCallback();
      server.close();
      setTimeout(() => process.exit(0), 500);
    }
  }, 60_000);
  inactivityTimer.unref();

  return new Promise((resolve, reject) => {
    if (process.platform !== "win32") {
      try {
        if (fs.existsSync(pipeName)) {
          try {
            fs.unlinkSync(pipeName);
          } catch (_) {}
        }
      } catch (_) {}
    }

    server.listen(pipeName, () => {
      if (process.platform !== "win32") {
        try {
          fs.chmodSync(pipeName, 0o600);
        } catch (_) {}
      }
      log(`Pipe server listening: ${pipeName}`);
      resolve(server);
    });
    server.on("error", reject);
  });
}

module.exports = {
  startPipeServer,
  getPipeName,
  computeWorkspaceHash: config.computeWorkspaceHash,
};
