"use strict";

/**
 * Auth: device flow, token refresh, proactive refresh timer.
 * All HTTP requests go only to the Airlock gateway (gatewayUrl). No direct Keycloak or other URLs.
 * Sign-in opens the verification URL in the default browser (same UX as Cursor enforcer).
 *
 * Refresh strategy (aligned with Cursor enforcer deviceAuth.ts):
 * - Proactive timer refreshes JWT 60s before expiry
 * - Exponential backoff on failure: 30s, 60s, 120s, 240s, max 300s
 * - Up to MAX_REFRESH_RETRIES before declaring session expired
 * - Credentials are NOT cleared on transient failure (may recover)
 */
const http = require("http");
const https = require("https");
const { exec } = require("child_process");
const {
  readCredentials,
  writeCredentialsAsync,
  getConfigDir,
} = require("./config.js");

const MAX_REFRESH_RETRIES = 10;

/** Module-level logger — set by callers via setLogger(). Defaults to stderr. */
let _log = (msg) => {
  try { process.stderr.write(`[Airlock Auth] ${msg}\n`); } catch (_) {}
};

function setLogger(fn) {
  if (typeof fn === "function") _log = fn;
}

function ensureGatewayPath(path) {
  const s = String(path || "").trim();
  if (!s.startsWith("/") || s.startsWith("//") || /^https?:\/\//i.test(s)) {
    throw new Error("Auth: path must be a relative gateway path (e.g. /v1/auth/device), not an absolute URL");
  }
}

function postJson(gatewayUrl, path, body, token) {
  ensureGatewayPath(path);
  return new Promise((resolve, reject) => {
    const url = new URL(path, gatewayUrl);
    const transport = url.protocol === "https:" ? https : http;
    const data = JSON.stringify(body);
    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(data),
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname,
        method: "POST",
        headers,
        timeout: 15000,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk) => (raw += chunk));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(raw ? JSON.parse(raw) : {});
            } catch {
              reject(new Error("Invalid JSON response"));
            }
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 200)}`));
          }
        });
      }
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function getJson(gatewayUrl, path, token) {
  ensureGatewayPath(path);
  return new Promise((resolve, reject) => {
    const url = new URL(path, gatewayUrl);
    const transport = url.protocol === "https:" ? https : http;
    const headers = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname + url.search,
        method: "GET",
        headers,
        timeout: 10000,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk) => (raw += chunk));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(raw ? JSON.parse(raw) : {});
            } catch {
              reject(new Error("Invalid JSON response"));
            }
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 200)}`));
          }
        });
      }
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    req.on("error", reject);
    req.end();
  });
}

/**
 * Start device authorization; returns { deviceCode, userCode, verificationUri, verificationUriComplete, expiresIn, interval }.
 */
async function startDeviceAuth(gatewayUrl) {
  return postJson(gatewayUrl, "/v1/auth/device", {});
}

/**
 * Poll for device token; returns { completed, accessToken?, refreshToken? } or { error }.
 */
async function pollDeviceToken(gatewayUrl, deviceCode) {
  return postJson(gatewayUrl, "/v1/auth/device/token", { deviceCode });
}

/**
 * Refresh access token using stored refresh token.
 * Logs diagnostic info on failure (aligned with Cursor enforcer pattern).
 * Does NOT clear credentials on failure — transient errors should not kill the session.
 */
async function refresh() {
  const creds = readCredentials();
  if (!creds || !creds.refreshToken || !creds.gatewayUrl) {
    _log("Refresh skipped: no refresh token or gateway URL stored");
    return false;
  }

  try {
    const resp = await postJson(creds.gatewayUrl, "/v1/auth/enforcer/refresh", {
      refreshToken: creds.refreshToken,
    });
    if (!resp || !resp.accessToken) {
      _log("Refresh failed: gateway returned no access token");
      return false;
    }

    await writeCredentialsAsync({
      ...creds,
      accessToken: resp.accessToken,
      refreshToken: resp.refreshToken || creds.refreshToken,
    });
    return true;
  } catch (e) {
    _log(`Refresh failed: ${e.message || e}`);
    // Don't clear credentials — failure may be transient (gateway down, network issue)
    return false;
  }
}

/**
 * Return a fresh access token, refreshing if expiry is within 60s.
 * Retries up to 2 times with 1s delay for on-demand callers (e.g. status command).
 */
async function ensureFreshToken() {
  const creds = readCredentials();
  if (!creds || !creds.accessToken) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(creds.accessToken.split(".")[1], "base64url").toString("utf8")
    );
    const expiresAt = (payload.exp || 0) * 1000;
    const refreshAt = expiresAt - 60_000;
    if (Date.now() >= refreshAt) {
      // Retry refresh up to 2 extra times with short delay
      for (let attempt = 0; attempt < 3; attempt++) {
        const ok = await refresh();
        if (ok) {
          const updated = readCredentials();
          return updated ? updated.accessToken : null;
        }
        if (attempt < 2) {
          _log(`Refresh attempt ${attempt + 1} failed, retrying in 1s...`);
          await new Promise(r => setTimeout(r, 1000));
        }
      }
      _log("All refresh attempts failed — token may be expired");
      return null;
    }
    return creds.accessToken;
  } catch {
    // Malformed JWT — try refresh with retry
    for (let attempt = 0; attempt < 3; attempt++) {
      const ok = await refresh();
      if (ok) {
        const updated = readCredentials();
        return updated ? updated.accessToken : null;
      }
      if (attempt < 2) {
        await new Promise(r => setTimeout(r, 1000));
      }
    }
    return null;
  }
}

/**
 * Open URL in the default system browser (same UX as Cursor: "Open Browser to Sign In").
 */
function openBrowser(url) {
  const u = String(url || "").trim();
  if (!u || !/^https?:\/\//i.test(u)) return;
  const cmd =
    process.platform === "win32"
      ? `start "" "${u.replace(/"/g, '\\"')}"`
      : process.platform === "darwin"
        ? `open "${u.replace(/"/g, '\\"')}"`
        : `xdg-open "${u.replace(/"/g, '\\"')}"`;
  exec(cmd, (err) => {
    if (err) {
      try { process.stderr.write(`Could not open browser: ${err.message}\n`); } catch (_) {}
    }
  });
}

/**
 * Run device flow: start auth, open browser to sign-in URL, poll until done, then save tokens.
 * Same flow as Cursor enforcer: user signs in via browser (device code flow proxied by gateway).
 */
async function login(gatewayUrl, log) {
  const logger = log || (() => {});

  const start = await startDeviceAuth(gatewayUrl);
  if (!start.deviceCode || !start.userCode) {
    throw new Error("Failed to start device authorization");
  }

  const loginUrl = start.verificationUriComplete || start.verificationUri;
  const expiresIn = start.expiresIn || 600;
  const intervalSec = (start.interval || 5) * 1000;
  const deadline = Date.now() + expiresIn * 1000;

  // Normalize user code to 6 chars for display (backend may return 6 or 8)
  const userCodeDisplay = String(start.userCode).replace(/\D/g, "").slice(0, 6)
    || String(start.userCode).replace(/\s/g, "").slice(0, 6)
    || start.userCode;

  logger("");
  logger("Airlock sign-in (browser)");
  logger("====================================");
  logger(`Gateway: ${gatewayUrl}`);
  logger(`Sign-in URL: ${loginUrl}`);
  logger(`Code (if prompted): ${userCodeDisplay}`);
  openBrowser(loginUrl);
  logger("Opening browser for sign-in...");
  logger("Waiting for you to complete sign-in...");
  logger("");

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, intervalSec));

    const poll = await pollDeviceToken(gatewayUrl, start.deviceCode);
    if (poll.completed && poll.accessToken) {
      await writeCredentialsAsync({
        accessToken: poll.accessToken,
        refreshToken: poll.refreshToken || "",
        gatewayUrl: gatewayUrl.replace(/\/$/, ""),
      });
      logger("Sign-in successful. Tokens saved.");
      return true;
    }
    if (poll.error === "authorization_pending" || poll.error === "slow_down") {
      continue;
    }
    if (poll.error) {
      throw new Error(`Login failed: ${poll.error}`);
    }
  }

  throw new Error("Login timed out. Please try again.");
}

/**
 * Proactive refresh timer — schedules JWT refresh 60s before expiry.
 * Uses exponential backoff on failure (30s, 60s, 120s, 240s, max 300s)
 * up to MAX_REFRESH_RETRIES. Aligned with Cursor enforcer's startRefreshTimer().
 *
 * @param { (msg: string) => void } [log] - Logger function
 * @returns {{ dispose: () => void }} - Call dispose() to stop the timer
 */
function startRefreshTimer(log) {
  const logger = log || _log;
  let timer = null;
  let retryCount = 0;
  let disposed = false;

  const scheduleNext = () => {
    if (disposed) return;
    const creds = readCredentials();
    if (!creds || !creds.accessToken) return;

    try {
      const payload = JSON.parse(
        Buffer.from(creds.accessToken.split(".")[1], "base64url").toString("utf8")
      );
      const expiresAt = (payload.exp || 0) * 1000;
      const refreshAt = expiresAt - 60_000; // 60s before expiry
      const delay = Math.max(0, refreshAt - Date.now());

      timer = setTimeout(async () => {
        if (disposed) return;
        const ok = await refresh();
        if (ok) {
          retryCount = 0;
          logger("Token refreshed proactively.");
          scheduleNext(); // Schedule next refresh
        } else {
          retryCount++;
          if (retryCount >= MAX_REFRESH_RETRIES) {
            logger(`Session expired: ${MAX_REFRESH_RETRIES} refresh retries exhausted. Run 'sign-in' again.`);
            return; // Stop retrying
          }
          // Exponential backoff: 30s, 60s, 120s, 240s, max 300s
          const retryDelay = Math.min(30_000 * Math.pow(2, retryCount - 1), 300_000);
          logger(`Refresh retry ${retryCount}/${MAX_REFRESH_RETRIES} in ${Math.round(retryDelay / 1000)}s...`);
          timer = setTimeout(() => {
            if (!disposed) scheduleNext();
          }, retryDelay);
        }
      }, delay);
    } catch {
      // Malformed JWT — nothing to schedule
      logger("Cannot schedule refresh: malformed JWT");
    }
  };

  scheduleNext();
  return {
    dispose: () => {
      disposed = true;
      if (timer) clearTimeout(timer);
    },
  };
}

module.exports = {
  postJson,
  getJson,
  startDeviceAuth,
  pollDeviceToken,
  refresh,
  ensureFreshToken,
  login,
  readCredentials,
  setLogger,
  startRefreshTimer,
};
