"use strict";

/**
 * Secure storage for credentials and state.
 * When the optional dependency "keytar" is installed, data is stored in the OS keychain
 * (Windows Credential Manager, macOS Keychain, Linux Secret Service).
 * Otherwise falls back to files in the config directory with mode 0600.
 *
 * Keytar is async; we load into an in-memory cache at startup so that readCredentials/readState
 * can stay synchronous for existing callers.
 */

const path = require("path");
const os = require("os");
const fs = require("fs");

const SERVICE_NAME = "Airlock Enforcer";
const ACCOUNT_CREDENTIALS = "credentials";
const ACCOUNT_STATE = "state";

let keytar = null;
let useKeytar = null;
let configDir = null;
let credentialsCache = null;
let stateCache = null;
let cacheLoaded = false;

function getConfigDir() {
  if (configDir) return configDir;
  configDir =
    process.env.AIRLOCK_CONFIG_DIR ||
    path.join(os.homedir(), ".config", "airlock-enforcer");
  return configDir;
}

function ensureConfigDir() {
  const dir = getConfigDir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

function tryLoadKeytar() {
  if (useKeytar !== null) return useKeytar;
  try {
    keytar = require("keytar");
    useKeytar = true;
    return true;
  } catch (e) {
    useKeytar = false;
    return false;
  }
}

function credentialsPath() {
  return path.join(ensureConfigDir(), "credentials.json");
}

function statePath() {
  return path.join(ensureConfigDir(), "state.json");
}

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

function writeFileSecure(filePath, data) {
  ensureConfigDir();
  fs.writeFileSync(filePath, data, { mode: 0o600 });
}

/**
 * Load credentials and state from keychain or file into in-memory cache.
 * Call once at daemon startup so that sync getCredentials/getState can return from cache.
 */
async function loadCacheAsync() {
  if (cacheLoaded) return;
  if (tryLoadKeytar() && keytar) {
    try {
      const [creds, state] = await Promise.all([
        keytar.getPassword(SERVICE_NAME, ACCOUNT_CREDENTIALS),
        keytar.getPassword(SERVICE_NAME, ACCOUNT_STATE),
      ]);
      credentialsCache = creds ? JSON.parse(creds) : null;
      stateCache = state ? JSON.parse(state) : {};
    } catch (e) {
      credentialsCache = null;
      stateCache = {};
    }
  } else {
    const credRaw = readFileSafe(credentialsPath());
    const stateRaw = readFileSafe(statePath());
    credentialsCache = credRaw ? JSON.parse(credRaw) : null;
    stateCache = stateRaw ? JSON.parse(stateRaw) : {};
  }
  cacheLoaded = true;
}

/**
 * Get credentials. Sync. Returns from cache (after loadCacheAsync) or from file.
 */
function getCredentials() {
  if (cacheLoaded && credentialsCache !== undefined) return credentialsCache;
  const raw = readFileSafe(credentialsPath());
  return raw ? JSON.parse(raw) : null;
}

/**
 * Set credentials. Async. Writes to keychain (if available) and updates cache.
 */
async function setCredentialsAsync(data) {
  const json = data == null ? "null" : JSON.stringify(data, null, 2);
  if (tryLoadKeytar() && keytar) {
    try {
      if (data == null) {
        await keytar.deletePassword(SERVICE_NAME, ACCOUNT_CREDENTIALS);
      } else {
        await keytar.setPassword(SERVICE_NAME, ACCOUNT_CREDENTIALS, json);
      }
      credentialsCache = data;
      return;
    } catch (e) {
      if (data == null) {
        try { fs.unlinkSync(credentialsPath()); } catch (_) {}
      } else {
        writeFileSecure(credentialsPath(), json);
      }
      credentialsCache = data;
      return;
    }
  }
  if (data == null) {
    try { fs.unlinkSync(credentialsPath()); } catch (_) {}
  } else {
    writeFileSecure(credentialsPath(), json);
  }
  credentialsCache = data;
}

/**
 * Clear stored credentials (sign-out). Async.
 */
async function clearCredentialsAsync() {
  return setCredentialsAsync(null);
}

/**
 * Get state. Sync. Returns from cache or file.
 */
function getState() {
  if (cacheLoaded && stateCache !== undefined) return stateCache;
  const raw = readFileSafe(statePath());
  return raw ? JSON.parse(raw) : {};
}

/**
 * Set state. Async. Writes to keychain (if available) and updates cache.
 */
async function setStateAsync(data) {
  const json = JSON.stringify(data, null, 2);
  if (tryLoadKeytar() && keytar) {
    try {
      await keytar.setPassword(SERVICE_NAME, ACCOUNT_STATE, json);
      stateCache = data;
      return;
    } catch (e) {
      writeFileSecure(statePath(), json);
      stateCache = data;
      return;
    }
  }
  writeFileSecure(statePath(), json);
  stateCache = data;
}

function isUsingSecureStorage() {
  return tryLoadKeytar() && keytar;
}

module.exports = {
  getConfigDir,
  ensureConfigDir,
  loadCacheAsync,
  getCredentials,
  setCredentialsAsync,
  clearCredentialsAsync,
  getState,
  setStateAsync,
  isUsingSecureStorage,
};
