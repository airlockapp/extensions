"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const secureStorage = require("./secureStorage.js");

// ── Shared utility ─────────────────────────────────────────

/**
 * Generate a deterministic fallback workspace hash from a path (used for unpaired/legacy states).
 */
function generateWorkspaceId(workspacePath) {
  let normalized = path.resolve(workspacePath);
  if (process.platform === "win32") {
    normalized = normalized.toLowerCase().replace(/\\/g, "/");
  }
  return crypto.createHash("sha256").update(normalized).digest("hex").substring(0, 16);
}

/**
 * Find the nearest paired workspace ID by walking up the directory tree and looking for `.airlock`.
 * If an `.airlock` file exists, returns its workspaceId.
 * If none found, returns the fallback deterministic hash for startPath itself.
 */
function getWorkspaceId(startPath) {
  let curr = path.resolve(startPath);
  
  while (true) {
    const airlockPath = path.join(curr, ".airlock");
    if (fs.existsSync(airlockPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(airlockPath, "utf8"));
        if (data && data.workspaceId) {
          return data.workspaceId;
        }
      } catch (e) {
        // Ignore parse errors, continue looking or fallback
      }
    }
    const parent = path.dirname(curr);
    if (parent === curr) break; // Reached root
    curr = parent;
  }
  
  // ── Legacy Search ──
  // If no `.airlock` dotfile exists, check if the folder tree hashes to a legacy paired workspace
  // This allows `cmdRun` to discover legacy pairings and drop the robust `.airlock` dotfile automatically.
  try {
    const state = secureStorage.getState() || {};
    const wss = state.workspaces || {};
    curr = path.resolve(startPath);
    while (true) {
      const hash = generateWorkspaceId(curr);
      if (wss[hash]) {
        return hash;
      }
      const parent = path.dirname(curr);
      if (parent === curr) break; // Reached root
      curr = parent;
    }
  } catch (e) {
    // Ignore keychain errors during offline tree walking
  }

  // Pure fallback: return deterministic hash for startPath itself
  return generateWorkspaceId(startPath);
}

// Keep export aliases so existing callers remain unbroken
const computeWorkspaceHash = generateWorkspaceId;
const findWorkspaceHash = getWorkspaceId;

// ── Config dir ─────────────────────────────────────────────

function getConfigDir() {
  return secureStorage.getConfigDir();
}

function ensureConfigDir() {
  return secureStorage.ensureConfigDir();
}

// ── Cache loading ──────────────────────────────────────────

/**
 * Load credentials and state from keychain or file into cache.
 * Also performs one-time migration of legacy flat state to per-workspace format.
 * Call once at daemon startup (e.g. in cli main) before any read.
 */
async function loadCacheAsync() {
  await secureStorage.loadCacheAsync();
  await _migrateLegacyState();
}

/**
 * Migrate legacy flat state (routingToken, encryptionKey, pairedKeys, autoMode, failMode
 * at top level) into the per-workspace format under state.workspaces[hash].
 * Safe to call multiple times — only migrates if legacy fields exist.
 */
async function _migrateLegacyState() {
  const state = readState();
  // Already migrated or fresh install
  if (!state.routingToken && !state.encryptionKey && !state.pairedKeys) return;
  // Determine workspace hash for migration
  const wsPath = process.env.AIRLOCK_WORKSPACE || process.cwd();
  const wsHash = computeWorkspaceHash(wsPath);
  const ws = state.workspaces?.[wsHash] || {};
  // Copy legacy fields into workspace entry (don't overwrite if already set)
  if (!ws.routingToken && state.routingToken) ws.routingToken = state.routingToken;
  if (!ws.encryptionKey && state.encryptionKey) ws.encryptionKey = state.encryptionKey;
  if (!ws.pairedKeys && state.pairedKeys) ws.pairedKeys = state.pairedKeys;
  if (ws.autoMode === undefined && state.autoMode !== undefined) ws.autoMode = state.autoMode;
  if (ws.failMode === undefined && state.failMode !== undefined) ws.failMode = state.failMode;
  ws.workspacePath = ws.workspacePath || wsPath;
  // Write workspace entry
  if (!state.workspaces) state.workspaces = {};
  state.workspaces[wsHash] = ws;
  // Remove legacy top-level fields
  delete state.routingToken;
  delete state.encryptionKey;
  delete state.pairedKeys;
  delete state.autoMode;
  delete state.failMode;
  await writeStateAsync(state);
}

// ── Credentials (GLOBAL) ──────────────────────────────────

function readCredentials() {
  return secureStorage.getCredentials();
}

async function writeCredentialsAsync(data) {
  return secureStorage.setCredentialsAsync(data);
}

async function clearCredentialsAsync() {
  return secureStorage.clearCredentialsAsync();
}

// ── Raw state access ──────────────────────────────────────

function readState() {
  return secureStorage.getState();
}

async function writeStateAsync(data) {
  return secureStorage.setStateAsync(data);
}

// ── Per-workspace state helpers ───────────────────────────

function _getWs(wsHash) {
  const state = readState();
  return (state.workspaces && state.workspaces[wsHash]) || {};
}

async function _setWsFieldAsync(wsHash, field, value) {
  const state = readState();
  if (!state.workspaces) state.workspaces = {};
  if (!state.workspaces[wsHash]) state.workspaces[wsHash] = {};
  state.workspaces[wsHash][field] = value;
  await writeStateAsync(state);
}

// ── Pairing (PER-WORKSPACE) ──────────────────────────────

function getRoutingToken(wsHash) {
  return _getWs(wsHash).routingToken || null;
}

function getEncryptionKey(wsHash) {
  return _getWs(wsHash).encryptionKey || null;
}

function getPairedKeys(wsHash) {
  return _getWs(wsHash).pairedKeys || {};
}

async function storeRoutingTokenAsync(wsHash, token) {
  await _setWsFieldAsync(wsHash, "routingToken", token);
}

async function storeEncryptionKeyAsync(wsHash, key) {
  await _setWsFieldAsync(wsHash, "encryptionKey", key);
}

async function storePairedKeyAsync(wsHash, signerKeyId, publicKey, deviceId) {
  const state = readState();
  if (!state.workspaces) state.workspaces = {};
  if (!state.workspaces[wsHash]) state.workspaces[wsHash] = {};
  const ws = state.workspaces[wsHash];
  ws.pairedKeys = ws.pairedKeys || {};
  ws.pairedKeys[signerKeyId] = {
    publicKey,
    deviceId,
    pairedAt: new Date().toISOString(),
  };
  await writeStateAsync(state);
}

async function clearPairingAsync(wsHash) {
  const state = readState();
  if (state.workspaces && state.workspaces[wsHash]) {
    const ws = state.workspaces[wsHash];
    delete ws.routingToken;
    delete ws.encryptionKey;
    delete ws.pairedKeys;
    await writeStateAsync(state);
  }
}

/** Store workspace path in workspace entry (for display in status). */
async function storeWorkspacePathAsync(wsHash, wsPath) {
  await _setWsFieldAsync(wsHash, "workspacePath", wsPath);
}

// ── Mode (GLOBAL) ─────────────────────────────────────────

/** "dev" | "prod". Default prod. */
function getMode() {
  const state = readState();
  const m = state.airlockMode;
  return m === "dev" || m === "prod" ? m : "prod";
}

/** Dev gateway URL; only used when mode is dev. Default https://localhost:7145 */
function getDevGatewayUrl() {
  const state = readState();
  const u = state.devGatewayUrl;
  return typeof u === "string" && u.trim()
    ? u.trim().replace(/\/$/, "")
    : "https://localhost:7145";
}

/** Set mode and optional dev gateway URL; persists to state. */
async function setModeAsync(mode, devGatewayUrl) {
  const state = readState();
  state.airlockMode = mode === "dev" || mode === "prod" ? mode : "prod";
  if (mode === "dev" && devGatewayUrl != null) {
    state.devGatewayUrl = String(devGatewayUrl).trim().replace(/\/$/, "") || "https://localhost:7145";
  } else if (mode === "prod") {
    delete state.devGatewayUrl;
  }
  await writeStateAsync(state);
  applyTlsFromMode();
}

/** Set NODE_TLS_REJECT_UNAUTHORIZED from current mode (dev = allow self-signed). */
function applyTlsFromMode() {
  if (getMode() === "dev") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  } else {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
  }
}

// ── Auto-mode (PER-WORKSPACE) ─────────────────────────────

/** Read auto-mode flag. Default true (enforcement active). */
function readAutoMode(wsHash) {
  return _getWs(wsHash).autoMode !== false;
}

/** Set auto-mode flag. */
async function writeAutoModeAsync(wsHash, enabled) {
  await _setWsFieldAsync(wsHash, "autoMode", !!enabled);
}

// ── Fail mode (PER-WORKSPACE) ─────────────────────────────

/** "failClosed" | "failOpen". Env var takes precedence, then per-workspace config, then default. */
function getFailMode(wsHash) {
  const env = process.env.AIRLOCK_FAIL_MODE;
  if (env === "failOpen" || env === "failClosed") return env;
  if (wsHash) {
    const m = _getWs(wsHash).failMode;
    if (m === "failOpen") return "failOpen";
  }
  return "failClosed";
}

/** Set fail mode for a workspace. */
async function setFailModeAsync(wsHash, mode) {
  const fm = mode === "failOpen" || mode === "open" ? "failOpen" : "failClosed";
  await _setWsFieldAsync(wsHash, "failMode", fm);
}

// ── Auto-approve patterns (PER-WORKSPACE) ─────────────────

/** Get auto-approve patterns for a workspace. */
function getAutoApprovePatterns(wsHash) {
  return _getWs(wsHash).autoApprovePatterns || [];
}

/** Add an auto-approve pattern. */
async function addAutoApprovePatternAsync(wsHash, pattern) {
  const state = readState();
  if (!state.workspaces) state.workspaces = {};
  if (!state.workspaces[wsHash]) state.workspaces[wsHash] = {};
  const ws = state.workspaces[wsHash];
  ws.autoApprovePatterns = ws.autoApprovePatterns || [];
  const trimmed = pattern.trim();
  if (!trimmed) return;
  if (!ws.autoApprovePatterns.includes(trimmed)) {
    ws.autoApprovePatterns.push(trimmed);
    await writeStateAsync(state);
  }
}

/** Remove an auto-approve pattern. Returns true if found and removed. */
async function removeAutoApprovePatternAsync(wsHash, pattern) {
  const state = readState();
  const ws = state.workspaces?.[wsHash];
  if (!ws || !ws.autoApprovePatterns) return false;
  const trimmed = pattern.trim();
  const idx = ws.autoApprovePatterns.indexOf(trimmed);
  if (idx === -1) return false;
  ws.autoApprovePatterns.splice(idx, 1);
  await writeStateAsync(state);
  return true;
}

/**
 * Check if a command matches any auto-approve pattern.
 * Supports regex (/pattern/flags) and substring (case-insensitive includes).
 * Same logic as cursor enforcer's _isAutoApproved.
 */
function isAutoApproved(wsHash, commandText) {
  const patterns = getAutoApprovePatterns(wsHash);
  if (!patterns || patterns.length === 0) return false;

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

// ── Exports ───────────────────────────────────────────────

module.exports = {
  computeWorkspaceHash,
  findWorkspaceHash,
  getConfigDir,
  ensureConfigDir,
  loadCacheAsync,
  readCredentials,
  writeCredentialsAsync,
  clearCredentialsAsync,
  readState,
  writeStateAsync,
  // Per-workspace pairing
  getRoutingToken,
  getEncryptionKey,
  getPairedKeys,
  storeRoutingTokenAsync,
  storeEncryptionKeyAsync,
  storePairedKeyAsync,
  clearPairingAsync,
  storeWorkspacePathAsync,
  // Global mode
  getMode,
  getDevGatewayUrl,
  setModeAsync,
  applyTlsFromMode,
  // Per-workspace settings
  readAutoMode,
  writeAutoModeAsync,
  getFailMode,
  setFailModeAsync,
  // Per-workspace auto-approve
  getAutoApprovePatterns,
  addAutoApprovePatternAsync,
  removeAutoApprovePatternAsync,
  isAutoApproved,
  isUsingSecureStorage: () => secureStorage.isUsingSecureStorage(),
};
