#!/usr/bin/env node
"use strict";

/**
 * Airlock Session Lifecycle Script — Claude Code
 * ================================================
 * Manages daemon lifecycle via SessionStart/SessionEnd hooks.
 *
 * Usage:
 *   node airlock-session.js start   — spawn daemon if credentials + pairing valid
 *   node airlock-session.js stop    — send shutdown to daemon via pipe
 *
 * INV-3 COMPLIANT: This script contains ZERO secrets.
 */

const { spawn } = require("child_process");
const net = require("net");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const LOG_PREFIX = "[Airlock Session]";

function log(msg) {
  try { process.stderr.write(`${LOG_PREFIX} ${msg}\n`); } catch {}
}

function computeWorkspaceHash(workspacePath) {
  let normalized = path.resolve(workspacePath);
  if (process.platform === "win32") {
    normalized = normalized.toLowerCase().replace(/\\/g, "/");
  }
  return crypto.createHash("sha256").update(normalized).digest("hex").substring(0, 16);
}

function getPipeName(hash) {
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\airlock-ws-${hash}`;
  }
  return `/tmp/airlock-ws-${hash}.sock`;
}

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    let resolved = false;
    const done = () => { if (!resolved) { resolved = true; resolve(data); } };
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => { data += c; });
    process.stdin.on("end", done);
    // Short timeout — SessionStart hook only has 5s total budget
    const timer = setTimeout(done, 500);
    timer.unref();
  });
}

function probePipe(pipeName) {
  return new Promise((resolve) => {
    const socket = net.createConnection(pipeName, () => {
      socket.end();
      resolve(true);
    });
    socket.setTimeout(1000);
    socket.on("timeout", () => { socket.destroy(); resolve(false); });
    socket.on("error", () => resolve(false));
  });
}

function sendPipeMessage(pipeName, message) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(pipeName, () => {
      socket.write(JSON.stringify(message) + "\n", "utf8");
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
}

function getConfigDir() {
  return process.env.AIRLOCK_CONFIG_DIR || path.join(
    process.env.HOME || process.env.USERPROFILE || "/tmp",
    ".config", "airlock-enforcer"
  );
}

async function hasCredentialsAndPairing(cwd) {
  try {
    const configPath = path.join(__dirname, "..", "daemon", "config.js");
    const config = require(configPath);
    await config.loadCacheAsync();
    
    const creds = config.readCredentials();
    if (!creds || !creds.gatewayUrl || !creds.accessToken) return false;
    
    const wsHash = config.findWorkspaceHash(cwd);
    const token = config.getRoutingToken(wsHash);
    const key = config.getEncryptionKey(wsHash);
    
    return !!(token && key);
  } catch (e) {
    // If we can't load config, err on the side of starting the daemon
    log(`Credentials check error (will try anyway): ${e.message}`);
    return true;
  }
}

async function handleStart(payload) {
  const cwd = payload.cwd || process.env.AIRLOCK_WORKSPACE || process.cwd();
  let wsHash;
  try {
    const config = require(path.join(__dirname, "..", "daemon", "config.js"));
    await config.loadCacheAsync();
    wsHash = config.findWorkspaceHash(cwd);
  } catch (e) {
    wsHash = computeWorkspaceHash(cwd);
  }
  const pipeName = getPipeName(wsHash);

  // Persist plugin auto-shim so commands can run `airlock-enforcer` seamlessly
  try {
    const cliPath = path.resolve(__dirname, "..", "daemon", "cli.js");
    const binDir = path.join(getConfigDir(), "bin");
    fs.mkdirSync(binDir, { recursive: true });

    // Bash shim
    const bashShimPath = path.join(binDir, "airlock-enforcer");
    const bashShim = `#!/bin/bash\nnode "${cliPath}" "$@"\n`;
    fs.writeFileSync(bashShimPath, bashShim, { encoding: "utf8", mode: 0o755 });

    // Windows CMD shim
    const cmdShimPath = path.join(binDir, "airlock-enforcer.cmd");
    const cmdShim = `@ECHO OFF\r\nnode "${cliPath}" %*\r\n`;
    fs.writeFileSync(cmdShimPath, cmdShim, "utf8");

    log(`Plugin shims created at: ${binDir}`);
  } catch (e) {
    log(`Warning: could not save plugin shims: ${e.message}`);
  }

  // Check if setup is complete
  const configured = await hasCredentialsAndPairing(cwd);
  if (!configured) {
    log("Not configured (no credentials/pairing) — skipping daemon start");
    process.exit(0);
  }

  // Check if daemon already running
  const alive = await probePipe(pipeName);
  if (alive) {
    log("Daemon already running — nothing to do");
    process.exit(0);
  }

  // Spawn daemon
  const daemonScript = path.join(__dirname, "..", "daemon", "cli.js");
  log(`Starting daemon: ${daemonScript} run (workspace=${cwd})`);
  const child = spawn(process.execPath, [daemonScript, "run"], {
    env: { ...process.env, AIRLOCK_WORKSPACE: cwd },
    detached: true,
    stdio: "ignore",
  });
  child.unref();

  // Wait for daemon to start and verify
  await new Promise(r => setTimeout(r, 1500));
  const started = await probePipe(pipeName);
  log(started ? "Daemon started successfully" : "Daemon may still be starting...");
  process.exit(0);
}

async function handleStop(payload) {
  const cwd = payload.cwd || process.env.AIRLOCK_WORKSPACE || process.cwd();
  const wsHash = computeWorkspaceHash(cwd);
  const pipeName = getPipeName(wsHash);

  const result = await sendPipeMessage(pipeName, { kind: "shutdown" });
  if (result) {
    log("Daemon shutdown requested");
  } else {
    log("Daemon not running or already stopped");
  }
  process.exit(0);
}

async function main() {
  const mode = process.argv[2] || "start";
  let stdinData = await readStdin();
  stdinData = stdinData.replace(/^\uFEFF/, "").trim();

  let payload = {};
  try {
    if (stdinData) payload = JSON.parse(stdinData);
  } catch {
    log("Warning: could not parse stdin");
  }

  if (mode === "start") {
    await handleStart(payload);
  } else if (mode === "stop") {
    await handleStop(payload);
  } else {
    log(`Unknown mode: ${mode}`);
    process.exit(1);
  }
}

main().catch((err) => {
  log(`Error: ${err.message || err}`);
  process.exit(0); // Don't block Claude on session hook errors
});
