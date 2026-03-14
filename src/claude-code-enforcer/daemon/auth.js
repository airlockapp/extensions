"use strict";

/**
 * Auth: device flow, token refresh.
 * All HTTP requests go only to the Airlock gateway (gatewayUrl). No direct Keycloak or other URLs.
 * Sign-in opens the verification URL in the default browser (same UX as Cursor enforcer).
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
 */
async function refresh() {
  const creds = readCredentials();
  if (!creds || !creds.refreshToken || !creds.gatewayUrl) return false;

  try {
    const resp = await postJson(creds.gatewayUrl, "/v1/auth/enforcer/refresh", {
      refreshToken: creds.refreshToken,
    });
    if (!resp || !resp.accessToken) return false;

    await writeCredentialsAsync({
      ...creds,
      accessToken: resp.accessToken,
      refreshToken: resp.refreshToken || creds.refreshToken,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Return a fresh access token, refreshing if expiry is within 60s.
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
      const ok = await refresh();
      if (!ok) return null;
      const updated = readCredentials();
      return updated ? updated.accessToken : null;
    }
    return creds.accessToken;
  } catch {
    const ok = await refresh();
    if (!ok) return null;
    const updated = readCredentials();
    return updated ? updated.accessToken : null;
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

module.exports = {
  postJson,
  getJson,
  startDeviceAuth,
  pollDeviceToken,
  refresh,
  ensureFreshToken,
  login,
  readCredentials,
};
