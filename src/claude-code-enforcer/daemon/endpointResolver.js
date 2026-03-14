"use strict";

/**
 * Resolves the Airlock gateway URL only. Probes are for discovering a local gateway instance
 * (localhost); the default is the release gateway. No Keycloak or other non-gateway URLs.
 */
const http = require("http");
const https = require("https");
const config = require("./config.js");

/** Default gateway for prod when no local gateway, config, or env is set (same as Cursor) */
const DEFAULT_RELEASE_GATEWAY = "https://gw.airlocks.io";

/** Local gateway probe URLs only (used to discover which local port is the gateway) */
const PROBE_URLS = [
  "https://localhost:7145/echo",
  "http://localhost:5145/echo",
  "https://127.0.0.1:7145/echo",
  "http://127.0.0.1:5145/echo",
  "http://127.0.0.1:7771/healthz",
  "http://127.0.0.1:7772/healthz",
  "http://localhost:7771/healthz",
];

/**
 * Probe a URL with GET; returns true if 2xx. 2s timeout.
 */
function probeHealth(url) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 2000);
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      clearTimeout(timeout);
      return resolve(false);
    }
    const transport = parsed.protocol === "https:" ? https : http;
    const req = transport.get(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        timeout: 2000,
        rejectUnauthorized: false,
      },
      (res) => {
        clearTimeout(timeout);
        resolve(res.statusCode >= 200 && res.statusCode < 300);
        res.resume();
      }
    );
    req.on("error", () => {
      clearTimeout(timeout);
      resolve(false);
    });
  });
}

/**
 * Resolve the Airlock Gateway URL.
 * Priority (aligned with Cursor dev mode):
 *   (1) Already-saved gateway in credentials (so login with no args after first run works)
 *   (2) Environment AIRLOCK_GATEWAY_URL
 *   (3) Probe local Gateway / HE daemon (PROBE_URLS)
 *   (4) Default release gateway (DEFAULT_RELEASE_GATEWAY)
 *
 * @param { (msg: string) => void } [log] - Optional logger (e.g. stderr)
 * @returns {{ url: string, source: "config" | "env" | "daemon" | "default" }}
 */
async function resolveEndpoint(log) {
  const logger = log || (() => {});

  const creds = config.readCredentials();
  if (creds && creds.gatewayUrl && creds.gatewayUrl.trim()) {
    logger(`Gateway: ${creds.gatewayUrl} (saved)`);
    return { url: creds.gatewayUrl.trim().replace(/\/$/, ""), source: "config" };
  }

  const envUrl = process.env.AIRLOCK_GATEWAY_URL;
  if (envUrl && envUrl.trim()) {
    logger(`Gateway: ${envUrl.trim()} (env)`);
    return { url: envUrl.trim().replace(/\/$/, ""), source: "env" };
  }

  for (const probeUrl of PROBE_URLS) {
    const baseUrl = probeUrl.replace("/echo", "").replace("/healthz", "");
    logger(`Probing ${probeUrl}...`);
    try {
      const ok = await probeHealth(probeUrl);
      if (ok) {
        logger(`Gateway: ${baseUrl} (local)`);
        return { url: baseUrl, source: "daemon" };
      }
    } catch (_) {}
  }

  logger(`Gateway: ${DEFAULT_RELEASE_GATEWAY} (default)`);
  return { url: DEFAULT_RELEASE_GATEWAY, source: "default" };
}

module.exports = {
  DEFAULT_RELEASE_GATEWAY,
  PROBE_URLS,
  resolveEndpoint,
};
