#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");
const auth = require("./auth.js");
const config = require("./config.js");
const pairing = require("./pairing.js");
const pipeServer = require("./pipeServer.js");
const endpointResolver = require("./endpointResolver.js");

const LOG_PREFIX = "[Airlock Daemon]";

function log(msg) {
  console.error(`${LOG_PREFIX} ${msg}`);
}

/** Resolve the workspace path and hash from env/cwd. */
function resolveWorkspace() {
  const wsPath = process.env.AIRLOCK_WORKSPACE || process.cwd();
  const wsHash = config.findWorkspaceHash(wsPath);
  return { wsPath, wsHash };
}

/** Resolve pipe name from workspace hash. */
function getPipeName(wsHash) {
  return process.platform === "win32"
    ? `\\\\.\\pipe\\airlock-ws-${wsHash}`
    : `/tmp/airlock-ws-${wsHash}.sock`;
}

async function getGatewayUrl() {
  if (config.getMode() === "dev") {
    return config.getDevGatewayUrl();
  }
  const creds = config.readCredentials();
  if (creds && creds.gatewayUrl && creds.gatewayUrl.trim()) {
    return creds.gatewayUrl.trim().replace(/\/$/, "");
  }
  if (process.env.AIRLOCK_GATEWAY_URL && process.env.AIRLOCK_GATEWAY_URL.trim()) {
    return process.env.AIRLOCK_GATEWAY_URL.trim().replace(/\/$/, "");
  }
  const resolved = await endpointResolver.resolveEndpoint(log);
  return resolved.url;
}

// ── Probe / stop daemon helpers ───────────────────────────

async function probePipe(pipeName) {
  return new Promise((resolve) => {
    const socket = net.createConnection(pipeName, () => { socket.end(); resolve(true); });
    socket.setTimeout(1000);
    socket.on("timeout", () => { socket.destroy(); resolve(false); });
    socket.on("error", () => resolve(false));
  });
}

async function stopDaemon(wsHash, logger) {
  const pipeName = getPipeName(wsHash);
  const result = await new Promise((resolve) => {
    const socket = net.createConnection(pipeName, () => {
      socket.write(JSON.stringify({ kind: "shutdown" }) + "\n", "utf8");
    });
    let raw = "";
    socket.setEncoding("utf8");
    socket.setTimeout(3000);
    socket.on("timeout", () => { socket.destroy(); resolve(null); });
    socket.on("data", (c) => { raw += c; });
    socket.on("end", () => {
      try { resolve(JSON.parse(raw)); } catch { resolve(null); }
    });
    socket.on("error", () => resolve(null));
  });
  if (result) {
    logger("Daemon shutdown requested.");
  } else {
    logger("Daemon not running or already stopped.");
  }
}

// ── Login / Logout ────────────────────────────────────────

async function cmdLogin(gatewayUrl) {
  let url = gatewayUrl && gatewayUrl.trim() ? gatewayUrl.trim().replace(/\/$/, "") : null;
  if (!url) {
    url = await getGatewayUrl();
  }
  await auth.login(url, log);
}

async function cmdLogout() {
  const { wsHash } = resolveWorkspace();
  await stopDaemon(wsHash, log);
  await config.clearCredentialsAsync();
  log("Signed out. Credentials cleared.");
}

// ── Shared Dotfile Helper ───────────────────────────────────

function ensureAirlockDotfile(wsPath, wsHash) {
  try {
    const dotfilePath = path.join(wsPath, ".airlock");
    if (!fs.existsSync(dotfilePath)) {
      fs.writeFileSync(dotfilePath, JSON.stringify({ workspaceId: wsHash }, null, 2), "utf8");
      log("Created .airlock workspace identity file.");
    }
    
    // Automatically ignore the dotfile in git (create .gitignore if missing)
    // Run this outside the `.airlock` existence check so previously dropped files get ignored too.
    const gitignorePath = path.join(wsPath, ".gitignore");
    let needsIgnore = true;
    if (fs.existsSync(gitignorePath)) {
      const gitignore = fs.readFileSync(gitignorePath, "utf8");
      if (gitignore.includes(".airlock")) {
        needsIgnore = false;
      }
    }
    if (needsIgnore) {
      fs.appendFileSync(gitignorePath, "\n# Airlock\n.airlock\n");
      log("Added .airlock to .gitignore.");
    }
  } catch (e) {
    log(`Warning: could not write .airlock file: ${e.message}`);
  }
}

// ── Pair / Unpair ─────────────────────────────────────────

async function cmdPair() {
  const url = await getGatewayUrl();
  if (!url) {
    console.error("Run 'login' first to set the gateway URL.");
    process.exit(1);
  }
  const token = await auth.ensureFreshToken();
  if (!token) {
    console.error("Not signed in. Run 'login' first.");
    process.exit(1);
  }
  const { wsPath, wsHash } = resolveWorkspace();

  // Drop robust `.airlock` dotfile and configure `.gitignore` immediately 
  // to permanently identify this workspace before the blocking gateway pair.
  ensureAirlockDotfile(wsPath, wsHash);

  const workspaceName = path.basename(wsPath);
  await pairing.pair(url, token, log, workspaceName, wsPath);

  // Store workspace path in state for display
  await config.storeWorkspacePathAsync(wsHash, wsPath);

  // Auto-start daemon after successful pairing
  const pipeName = getPipeName(wsHash);
  const alive = await probePipe(pipeName);

  if (alive) {
    log("Daemon already running.");
  } else {
    const daemonScript = path.join(__dirname, "cli.js");
    log("Starting daemon...");
    const child = spawn(process.execPath, [daemonScript, "run"], {
      env: { ...process.env, AIRLOCK_WORKSPACE: wsPath },
      detached: true,
      stdio: "ignore",
    });
    child.unref();
    await new Promise(r => setTimeout(r, 2000));
    const started = await probePipe(pipeName);
    log(started ? "Daemon started successfully." : "Daemon may still be starting...");
  }
}

async function cmdUnpair() {
  const { wsPath, wsHash } = resolveWorkspace();
  const creds = config.readCredentials();
  const routingToken = config.getRoutingToken(wsHash);
  if (!routingToken) {
    log("Not paired. Nothing to unpair.");
    return;
  }
  const gatewayUrl = (creds && creds.gatewayUrl && creds.gatewayUrl.trim())
    ? creds.gatewayUrl.trim().replace(/\/$/, "")
    : await getGatewayUrl();
  if (gatewayUrl) {
    const token = await auth.ensureFreshToken();
    try {
      await auth.postJson(gatewayUrl, "/v1/pairing/revoke", { routingToken }, token);
      log("Gateway revoke: OK");
    } catch (e) {
      log("Gateway revoke failed (non-fatal): " + (e.message || e));
    }
  }
  await config.clearPairingAsync(wsHash);
  
  // Clean up the `.airlock` dotfile
  try {
    const dotfilePath = path.join(wsPath, ".airlock");
    if (fs.existsSync(dotfilePath)) {
      fs.unlinkSync(dotfilePath);
      log("Removed .airlock workspace identity file.");
    }
  } catch (e) {
    log(`Warning: could not remove .airlock file: ${e.message}`);
  }

  await stopDaemon(wsHash, log);
  log("Unpaired. Routing token and encryption key cleared.");
}

// ── Status ────────────────────────────────────────────────

async function cmdStatus() {
  const { wsPath, wsHash } = resolveWorkspace();
  const creds = config.readCredentials();
  const mode = config.getMode();
  let effectiveGateway = null;
  if (mode === "dev") {
    effectiveGateway = config.getDevGatewayUrl();
  } else if (creds && creds.gatewayUrl && creds.gatewayUrl.trim()) {
    effectiveGateway = creds.gatewayUrl.trim().replace(/\/$/, "");
  }
  if (!effectiveGateway) effectiveGateway = await getGatewayUrl();

  console.log("Mode:", mode);
  console.log("Gateway:", effectiveGateway || "(none)");
  if (mode === "dev") {
    console.log("TLS: self-signed certificates allowed");
  }
  if (!creds) {
    console.log("Signed in: no — Run sign-in or login");
  } else {
    console.log("Signed in: yes");
  }
  console.log("Workspace:", wsPath);
  console.log("Paired:", config.getRoutingToken(wsHash) ? "yes" : "no");
  console.log("Fail mode:", config.getFailMode(wsHash));
  console.log("Auto mode:", config.readAutoMode(wsHash) ? "on (enforcement active)" : "off (disabled)");
  const patterns = config.getAutoApprovePatterns(wsHash);
  console.log("Auto-approve patterns:", patterns.length > 0 ? patterns.join(", ") : "(none)");
  console.log("Config dir:", config.getConfigDir());
}

// ── Mode ──────────────────────────────────────────────────

async function cmdDevMode(customUrl) {
  const url = (customUrl && String(customUrl).trim())
    ? String(customUrl).trim().replace(/\/$/, "")
    : "https://localhost:7145";
  await config.setModeAsync("dev", url);
  log("Dev mode ON. Gateway: " + url);
  log("Self-signed certificates are allowed (NODE_TLS_REJECT_UNAUTHORIZED=0).");
  console.log("Mode: dev");
  console.log("Gateway:", url);
  console.log("TLS: self-signed certificates allowed");
}

async function cmdProdMode() {
  await config.setModeAsync("prod");
  log("Prod mode ON. Gateway will resolve to https://gw.airlocks.io (or env/saved).");
  console.log("Mode: prod");
  console.log("Gateway: https://gw.airlocks.io (default)");
}

// ── Fail mode (per-workspace) ─────────────────────────────

async function cmdFailMode(value) {
  const { wsHash } = resolveWorkspace();
  if (!value || (value !== "open" && value !== "closed")) {
    const current = config.getFailMode(wsHash);
    console.log(`Fail mode: ${current}`);
    console.log("Usage: fail-mode <open|closed>");
    console.log("  open   — allow actions when daemon is unavailable");
    console.log("  closed — block actions when daemon is unavailable (default)");
    return;
  }
  const mode = value === "open" ? "failOpen" : "failClosed";
  await config.setFailModeAsync(wsHash, mode);
  log(`Fail mode set to: ${mode}`);
  console.log(`Fail mode: ${mode}`);
}

// ── Auto-on / off (per-workspace) ─────────────────────────

async function cmdAutoOn() {
  const { wsHash } = resolveWorkspace();
  await config.writeAutoModeAsync(wsHash, true);
  log("Auto-mode ON — enforcement active. All tool use will be gated.");
}

async function cmdAutoOff() {
  const { wsHash } = resolveWorkspace();
  await config.writeAutoModeAsync(wsHash, false);
  log("Auto-mode OFF — enforcement disabled. All tool use will be allowed.");
}

// ── Auto-approve patterns (per-workspace) ─────────────────

async function cmdApprove(pattern) {
  const { wsHash } = resolveWorkspace();
  if (!pattern || !pattern.trim()) {
    console.log("Usage: approve <pattern>");
    console.log("  Pattern can be a substring (e.g. 'git status') or regex (/^git\\s/i).");
    console.log("  Matching shell commands are auto-approved without gateway approval.");
    return;
  }
  await config.addAutoApprovePatternAsync(wsHash, pattern);
  log(`Auto-approve pattern added: ${pattern.trim()}`);
  console.log("Added:", pattern.trim());
  const all = config.getAutoApprovePatterns(wsHash);
  console.log(`Total patterns: ${all.length}`);
}

async function cmdDisapprove(pattern) {
  const { wsHash } = resolveWorkspace();
  if (!pattern || !pattern.trim()) {
    console.log("Usage: disapprove <pattern>");
    console.log("  Removes the exact pattern string from auto-approve list.");
    return;
  }
  const removed = await config.removeAutoApprovePatternAsync(wsHash, pattern);
  if (removed) {
    log(`Auto-approve pattern removed: ${pattern.trim()}`);
    console.log("Removed:", pattern.trim());
  } else {
    console.log("Pattern not found:", pattern.trim());
  }
}

async function cmdPatterns() {
  const { wsHash } = resolveWorkspace();
  const patterns = config.getAutoApprovePatterns(wsHash);
  if (patterns.length === 0) {
    console.log("No auto-approve patterns configured for this workspace.");
    console.log("Add one with: approve <pattern>");
    return;
  }
  console.log(`Auto-approve patterns (${patterns.length}):`);
  for (const p of patterns) {
    console.log(`  ${p}`);
  }
}

// ── Run daemon ────────────────────────────────────────────

async function cmdRun() {
  const { wsPath, wsHash } = resolveWorkspace();
  const creds = config.readCredentials();
  if (!creds || !creds.gatewayUrl) {
    console.error("Not signed in. Run 'login <GATEWAY_URL>' first.");
    process.exit(1);
  }
  if (!config.getRoutingToken(wsHash)) {
    console.error("Not paired. Run 'pair' first.");
    process.exit(1);
  }

  // Retrofit legacy pairings (or heal missing files) by ensuring the dotfile/gitignore exists
  ensureAirlockDotfile(wsPath, wsHash);

  // Start presence WebSocket
  let presenceClient = null;
  try {
    const { PresenceClient } = require("./presenceClient.js");
    presenceClient = new PresenceClient("Claude", log);
    const tokenGetter = async () => auth.ensureFreshToken();
    const workspaceName = path.basename(wsPath);
    await presenceClient.connect(creds.gatewayUrl, tokenGetter, pairing.getEnforcerId(wsPath), workspaceName);
  } catch (e) {
    log(`Presence client not available: ${e.message || e}`);
  }

  // Clean shutdown callback
  const onShutdown = () => {
    if (presenceClient) presenceClient.dispose();
  };

  log(`Workspace: ${wsPath}`);
  await pipeServer.startPipeServer(wsPath, log, onShutdown);
  log("Daemon running. Leave this process running; Claude Code will connect to the pipe.");
  log("Press Ctrl+C to stop.");

  process.on("SIGINT", () => {
    onShutdown();
    process.exit(0);
  });
}

// ── Help ──────────────────────────────────────────────────

function printHelp() {
  console.log(`
Airlock Enforcer Daemon — Claude Code plugin

Usage: node cli.js <command> [options]

Commands:
  login [GATEWAY_URL]   Sign in (opens browser). Saves tokens to config dir.
  sign-in               Alias for login.
  sign-out              Sign out; clear stored credentials.
  dev-mode [URL]        Use dev gateway (default https://localhost:7145). Allows self-signed certs.
  prod-mode             Use prod gateway (default https://gw.airlocks.io). Strict TLS.
  pair                  Pair with mobile app (requires sign-in). Saves routing token and encryption key.
  unpair                Unpair from mobile approver; clear routing token and encryption key.
  run                   Start the pipe server for the current workspace (or AIRLOCK_WORKSPACE).
  auto-on               Enable enforcement (default). Tool use is gated through gateway.
  auto-off              Disable enforcement. All tool use is allowed without gateway.
  status                Show mode, gateway, sign-in, pairing, and auto-approve status.
  fail-mode <open|closed> Set fail mode (open=allow, closed=block when daemon unavailable).
  approve <pattern>     Add auto-approve pattern (substring or /regex/). Matched commands skip gateway.
  disapprove <pattern>  Remove an auto-approve pattern.
  patterns              List current auto-approve patterns for this workspace.

  All per-workspace commands (pair, unpair, auto-on/off, fail-mode, approve, disapprove, patterns)
  use AIRLOCK_WORKSPACE or cwd to determine the workspace.

Environment:
  AIRLOCK_CONFIG_DIR    Config directory (default: ~/.config/airlock-enforcer)
  AIRLOCK_GATEWAY_URL   Gateway URL (used when not in credentials and not passed to login)
  AIRLOCK_WORKSPACE     Workspace path for 'run' (default: cwd)
  AIRLOCK_FAIL_MODE     Override fail mode (takes precedence over stored config)

After 'login' and 'pair', run 'node cli.js run' in your project directory (or set
AIRLOCK_WORKSPACE). Then use Claude Code with the Airlock plugin in that workspace.
`);
}

// ── Main ──────────────────────────────────────────────────

async function main() {
  await config.loadCacheAsync();
  config.applyTlsFromMode();
  if (config.isUsingSecureStorage && config.isUsingSecureStorage()) {
    log("Using OS keychain for credentials and keys.");
  }

  const cmd = (process.argv[2] || "help").toLowerCase();
  const cmdNorm = cmd === "sign-in" ? "login" : cmd;
  switch (cmdNorm) {
    case "login":
      await cmdLogin(process.argv[3]);
      break;
    case "sign-out":
    case "logout":
      await cmdLogout();
      break;
    case "dev-mode":
      await cmdDevMode(process.argv[3]);
      break;
    case "prod-mode":
      await cmdProdMode();
      break;
    case "pair":
      await cmdPair();
      break;
    case "unpair":
      await cmdUnpair();
      break;
    case "status":
      await cmdStatus();
      break;
    case "run":
      await cmdRun();
      break;
    case "auto-on":
      await cmdAutoOn();
      break;
    case "auto-off":
      await cmdAutoOff();
      break;
    case "fail-mode":
      await cmdFailMode(process.argv[3]);
      break;
    case "approve":
      await cmdApprove(process.argv.slice(3).join(" "));
      break;
    case "disapprove":
      await cmdDisapprove(process.argv.slice(3).join(" "));
      break;
    case "patterns":
      await cmdPatterns();
      break;
    case "help":
    case "-h":
    case "--help":
    default:
      printHelp();
      break;
  }

  // Explicitly exit so short-lived commands (status, login, approve) don't hang
  // on lingering keep-alive sockets. The 'run' command is the daemon so it stays alive.
  if (cmdNorm !== "run") {
    process.exit(0);
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
