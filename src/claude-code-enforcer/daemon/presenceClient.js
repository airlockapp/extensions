"use strict";

/**
 * Presence WebSocket client for Claude Code enforcer.
 * Port of cursor's presenceClient.ts — connects to WS /v1/ws for real-time presence.
 *
 * Features:
 * - Token auth via query param + header
 * - Capabilities hello on connect
 * - Application-level ping/pong
 * - Handle refresh.request and pairing.revoked messages
 * - Auto-reconnect with exponential backoff (1s → 30s)
 */

const RECONNECT_MIN_MS = 1000;
const RECONNECT_MAX_MS = 30_000;
const PING_TIMEOUT_MS = 10_000;

class PresenceClient {
  /**
   * @param {string} agentName e.g. "Claude Code"
   * @param {(msg: string) => void} log
   */
  constructor(agentName, log) {
    this._agentName = agentName;
    this._log = log || (() => {});
    this._ws = null;
    this._disposed = false;
    this._reconnectDelay = RECONNECT_MIN_MS;
    this._reconnectTimer = null;
    this._pingTimer = null;
    this._tokenGetter = null;
    this._gatewayUrl = null;
    this._deviceId = null;
    this._workspaceName = null;
  }

  /**
   * Connect to the presence WebSocket.
   * @param {string} gatewayUrl Base gateway URL (http/https)
   * @param {() => Promise<string>} tokenGetter Async function returning a fresh auth token
   * @param {string} deviceId Unique device/enforcer identifier
   */
  async connect(gatewayUrl, tokenGetter, deviceId, workspaceName) {
    this._gatewayUrl = gatewayUrl;
    this._tokenGetter = tokenGetter;
    this._deviceId = deviceId;
    this._workspaceName = workspaceName || "unknown";
    await this._connect();
  }

  async _connect() {
    if (this._disposed) return;

    let WebSocket;
    try {
      WebSocket = require("ws");
    } catch {
      this._log("Presence: ws module not available — skipping WebSocket connection");
      return;
    }

    let token;
    try {
      token = await this._tokenGetter();
    } catch {
      this._log("Presence: failed to get token — will retry");
      this._scheduleReconnect();
      return;
    }

    if (!token) {
      this._log("Presence: no token available — will retry");
      this._scheduleReconnect();
      return;
    }

    const base = this._gatewayUrl.replace(/\/$/, "").replace(/^http/, "ws");
    // Must include role + id query params (gateway requires them)
    const params = new URLSearchParams({
      role: "enforcer",
      id: this._deviceId,
    });
    if (token) {
      params.set("token", token);
    }
    const url = `${base}/v1/ws?${params.toString()}`;
    this._log(`Presence: connecting to ${base}/v1/ws?role=${params.get('role')}&id=${params.get('id')}&token=${token ? token.substring(0, 8) + '...' : 'none'}`);

    try {
      this._ws = new WebSocket(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        rejectUnauthorized: !process.env.NODE_TLS_REJECT_UNAUTHORIZED || process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0" ? true : false,
      });
    } catch (e) {
      this._log(`Presence: connection error — ${e.message}`);
      this._scheduleReconnect();
      return;
    }

    this._ws.on("open", () => {
      this._log("Presence: connected");
      this._reconnectDelay = RECONNECT_MIN_MS;

      // Send capabilities hello (match cursor's format exactly)
      const hello = {
        msgType: "hello",
        capabilities: {
          harpVersion: "1.0",
          enforcerVersion: "1.0.0",
          supportsRefresh: "true",
        },
        workspaceName: this._workspaceName,
        enforcerLabel: this._agentName,
      };
      this._log(`Presence: sending hello: ${JSON.stringify(hello)}`);
      this._send(hello);
    });

    this._ws.on("message", (data) => {
      try {
        const text = data.toString();
        this._log(`Presence: received: ${text.substring(0, 200)}`);
        const msg = JSON.parse(text);
        this._handleMessage(msg);
      } catch {
        this._log(`Presence: invalid message — ${data.toString().substring(0, 100)}`);
      }
    });

    this._ws.on("close", (code, reason) => {
      this._log(`Presence: closed (code=${code}, reason=${reason || "none"})`);
      this._ws = null;
      this._clearPingTimer();
      if (!this._disposed) {
        this._scheduleReconnect();
      }
    });

    this._ws.on("error", (err) => {
      this._log(`Presence: error — ${err.message || err}`);
    });
  }

  _handleMessage(msg) {
    const type = msg.type || msg.msgType || "";

    switch (type) {
      case "ping":
        this._send({ msgType: "pong" });
        break;

      case "refresh.request":
        this._log("Presence: refresh requested — token will refresh on next API call");
        break;

      case "pairing.revoked":
        this._log("Presence: pairing revoked — stopping reconnection");
        this._disposed = true;
        if (this._ws) {
          this._ws.close(1000, "pairing revoked");
          this._ws = null;
        }
        break;

      default:
        this._log(`Presence: unknown message type=${type}`);
    }
  }

  _send(obj) {
    if (this._ws && this._ws.readyState === 1) {
      try {
        this._ws.send(JSON.stringify(obj));
      } catch {
        // Ignore send errors
      }
    }
  }

  _scheduleReconnect() {
    if (this._disposed || this._reconnectTimer) return;
    this._log(`Presence: reconnecting in ${this._reconnectDelay}ms`);
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      this._connect();
    }, this._reconnectDelay);
    this._reconnectDelay = Math.min(this._reconnectDelay * 2, RECONNECT_MAX_MS);
  }

  _clearPingTimer() {
    if (this._pingTimer) {
      clearTimeout(this._pingTimer);
      this._pingTimer = null;
    }
  }

  dispose() {
    this._disposed = true;
    this._clearPingTimer();
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    if (this._ws) {
      try { this._ws.close(1000, "daemon shutting down"); } catch {}
      this._ws = null;
    }
    this._log("Presence: disposed");
  }
}

module.exports = { PresenceClient };
