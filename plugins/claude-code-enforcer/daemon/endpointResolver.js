"use strict";

/**
 * Resolves the Airlock gateway URL only.
 * No local probing — the default is the production gateway.
 * Dev mode uses an explicit URL set via the dev-mode command.
 */
const config = require("./config.js");

/** Default gateway for prod (same as Cursor enforcer release builds) */
const DEFAULT_RELEASE_GATEWAY = "https://gw.airlocks.io";

/**
 * Resolve the Airlock Gateway URL.
 * Priority:
 *   (1) Already-saved gateway in credentials (so login with no args after first run works)
 *   (2) Environment AIRLOCK_GATEWAY_URL
 *   (3) Default release gateway (DEFAULT_RELEASE_GATEWAY)
 *
 * Note: Local/dev gateway is handled explicitly by the dev-mode command
 * which stores the URL in config. No localhost probing is performed.
 *
 * @param { (msg: string) => void } [log] - Optional logger (e.g. stderr)
 * @returns {{ url: string, source: "config" | "env" | "default" }}
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

  logger(`Gateway: ${DEFAULT_RELEASE_GATEWAY} (default)`);
  return { url: DEFAULT_RELEASE_GATEWAY, source: "default" };
}

module.exports = {
  DEFAULT_RELEASE_GATEWAY,
  resolveEndpoint,
};
