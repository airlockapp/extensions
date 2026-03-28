"use strict";

/**
 * Presence HTTP heartbeat client for Claude Code enforcer.
 * Sends periodic HTTP POST to /v1/presence/heartbeat to stay online.
 *
 * This replaces the WebSocket-based presence client to avoid
 * shipping the ws npm dependency with the plugin.
 *
 * Features:
 * - POST /v1/presence/heartbeat every 30 seconds
 * - Token auth via Bearer header
 * - Retry with exponential backoff on failure
 * - No external dependencies (uses Node.js built-in http/https)
 */

const http = require("http");
const https = require("https");

const HEARTBEAT_INTERVAL_MS = 30_000; // 30 seconds (gateway offline threshold is 90s)
const RETRY_MIN_MS = 5_000;
const RETRY_MAX_MS = 60_000;

class PresenceClient {
  /**
   * @param {string} agentName e.g. "Claude Code"
   * @param {(msg: string) => void} log
   */
  constructor(agentName, log) {
    this._agentName = agentName;
    this._log = log || (() => {});
    this._disposed = false;
    this._timer = null;
    this._retryDelay = RETRY_MIN_MS;
    this._tokenGetter = null;
    this._gatewayUrl = null;
    this._deviceId = null;
    this._workspaceName = null;
    this.onActivity = null; // callback for daemon keep-alive
  }

  /**
   * Start sending presence heartbeats.
   * @param {string} gatewayUrl Base gateway URL (http/https)
   * @param {() => Promise<string>} tokenGetter Async function returning a fresh auth token
   * @param {string} deviceId Unique device/enforcer identifier
   * @param {string} [workspaceName] Human-readable workspace name
   */
  async connect(gatewayUrl, tokenGetter, deviceId, workspaceName) {
    this._gatewayUrl = gatewayUrl;
    this._tokenGetter = tokenGetter;
    this._deviceId = deviceId;
    this._workspaceName = workspaceName || "unknown";

    // Send first heartbeat immediately
    await this._sendHeartbeat();

    // Schedule periodic heartbeats
    this._scheduleNext(HEARTBEAT_INTERVAL_MS);
  }

  async _sendHeartbeat() {
    if (this._disposed) return;

    let token;
    try {
      token = await this._tokenGetter();
    } catch {
      this._log("Presence: failed to get token — will retry");
      this._scheduleNext(this._retryDelay);
      this._retryDelay = Math.min(this._retryDelay * 2, RETRY_MAX_MS);
      return;
    }

    if (!token) {
      this._log("Presence: no token available — will retry");
      this._scheduleNext(this._retryDelay);
      this._retryDelay = Math.min(this._retryDelay * 2, RETRY_MAX_MS);
      return;
    }

    const base = this._gatewayUrl.replace(/\/$/, "");
    const url = `${base}/v1/presence/heartbeat`;
    const body = JSON.stringify({
      enforcerId: this._deviceId,
      workspaceName: this._workspaceName,
      enforcerLabel: this._agentName,
    });

    try {
      const result = await this._httpPost(url, body, token);
      if (result.status >= 200 && result.status < 300) {
        this._log(`Presence: heartbeat OK (${result.status})`);
        this._retryDelay = RETRY_MIN_MS; // reset backoff on success
        if (this.onActivity) this.onActivity();
      } else if (result.status === 401) {
        this._log("Presence: heartbeat 401 — token may be expired, will retry");
      } else {
        this._log(`Presence: heartbeat failed (HTTP ${result.status})`);
      }
    } catch (e) {
      this._log(`Presence: heartbeat error — ${e.message || e}`);
    }
  }

  /**
   * Simple HTTP POST using Node builtins.
   */
  _httpPost(url, body, token) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const transport = parsed.protocol === "https:" ? https : http;
      const data = Buffer.from(body, "utf8");

      const req = transport.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": data.length,
            Authorization: `Bearer ${token}`,
          },
          timeout: 10_000,
          rejectUnauthorized:
            !process.env.NODE_TLS_REJECT_UNAUTHORIZED ||
            process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0",
        },
        (res) => {
          let raw = "";
          res.on("data", (chunk) => (raw += chunk));
          res.on("end", () => resolve({ status: res.statusCode, body: raw }));
        }
      );

      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Heartbeat request timeout"));
      });
      req.on("error", reject);
      req.write(data);
      req.end();
    });
  }

  _scheduleNext(delayMs) {
    if (this._disposed) return;
    if (this._timer) {
      clearTimeout(this._timer);
    }
    this._timer = setTimeout(async () => {
      this._timer = null;
      await this._sendHeartbeat();
      if (!this._disposed) {
        this._scheduleNext(HEARTBEAT_INTERVAL_MS);
      }
    }, delayMs);
    this._timer.unref(); // Don't prevent process exit
  }

  dispose() {
    this._disposed = true;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    this._log("Presence: disposed");
  }
}

module.exports = { PresenceClient };
