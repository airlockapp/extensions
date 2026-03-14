"use strict";

/**
 * Pairing: initiate, poll, verify. All HTTP is via auth.postJson/auth.getJson to the Airlock gateway only.
 */
const crypto = require("crypto");
const auth = require("./auth.js");
const config = require("./config.js");
const { generateX25519KeyPair, deriveSharedKey } = require("./crypto.js");

const path = require("path");

/**
 * Generate a deterministic per-workspace enforcer ID.
 * Same workspace path always produces the same ID.
 * @param {string} workspacePath Absolute workspace directory path
 * @returns {string} e.g. "enf-claude-a1b2c3d4e5f6"
 */
function getEnforcerId(workspacePath) {
  let normalized = path.resolve(workspacePath);
  if (process.platform === "win32") normalized = normalized.toLowerCase();
  const hash = crypto.createHash("sha256").update(normalized).digest("hex").substring(0, 12);
  return `enf-claude-${hash}`;
}

const DEVICE_ID = "claude-code-" + require("os").hostname().replace(/\s/g, "-").slice(0, 32);

function postJson(gatewayUrl, path, body, token) {
  return auth.postJson(gatewayUrl, path, body, token);
}

function getJson(gatewayUrl, path, token) {
  return auth.getJson(gatewayUrl, path, token);
}

function verifyPairingResponse(response, log) {
  const logger = log || (() => {});
  const publicKeyBytes = Buffer.from(response.publicKey, "base64");

  let sigB64 = (response.signature || "").replace(/-/g, "+").replace(/_/g, "/");
  while (sigB64.length % 4 !== 0) sigB64 += "=";
  const signatureBytes = Buffer.from(sigB64, "base64");

  const base = `${response.signerKeyId}|${response.publicKey}|${response.pairingNonce}|${response.timestamp}`;
  const candidates = [];
  if (response.x25519PublicKey) {
    candidates.push(`${base}|${response.x25519PublicKey}`);
  }
  candidates.push(base);

  for (const canonical of candidates) {
    const message = Buffer.from(canonical, "utf-8");
    try {
      if (
        crypto.verify(null, message, { key: publicKeyBytes, format: "der", type: "spki" }, signatureBytes)
      ) {
        logger("Verify: ✓ passed");
        return true;
      }
    } catch (_) {}
    try {
      const keyObj = crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from("302a300506032b6570032100", "hex"),
          publicKeyBytes,
        ]),
        format: "der",
        type: "spki",
      });
      if (crypto.verify(null, message, keyObj, signatureBytes)) {
        logger("Verify: ✓ passed (raw)");
        return true;
      }
    } catch (_) {}
  }
  logger("Verify: ✗ failed");
  return false;
}

/**
 * Initiate pairing: POST /v1/pairing/initiate with deviceId, enforcerId, x25519PublicKey.
 * Returns { pairingNonce, pairingCode, expiresAt, ... }.
 */
async function initiatePairing(gatewayUrl, token, log, workspaceName, workspacePath) {
  const keyPair = generateX25519KeyPair();
  const enforcerId = getEnforcerId(workspacePath || process.cwd());
  const body = {
    deviceId: DEVICE_ID,
    gatewayUrl,
    enforcerId,
    x25519PublicKey: keyPair.publicKey,
    enforcerLabel: "Claude",
    workspaceName: workspaceName || "unknown",
  };
  const result = await postJson(gatewayUrl, "/v1/pairing/initiate", body, token);
  result._localX25519PrivateKey = keyPair.privateKey;
  return result;
}

/**
 * Poll pairing status: GET /v1/pairing/:nonce/status.
 * Returns { state, responseJson?, routingToken? }.
 */
async function pollPairingStatus(gatewayUrl, nonce, token) {
  return getJson(gatewayUrl, `/v1/pairing/${encodeURIComponent(nonce)}/status`, token);
}

/**
 * Run full pairing flow: initiate, print code, poll until Completed, verify, derive key, store.
 */
async function pair(gatewayUrl, token, log, workspaceName, workspacePath) {
  const logger = log || (() => {});

  const session = await initiatePairing(gatewayUrl, token, log, workspaceName, workspacePath);
  if (!session.pairingCode || !session.pairingNonce) {
    throw new Error("Failed to initiate pairing");
  }

  // Use exactly 6 characters for display (gateway contract is 6-digit; normalize if gateway returns more)
  const rawCode = String(session.pairingCode).replace(/\s/g, "").replace(/-/g, "");
  const pairingCode6 = rawCode.slice(0, 6);
  if (rawCode.length > 6) {
    logger("Note: Gateway returned a code longer than 6 chars; using first 6.");
  }

  const privateKey = session._localX25519PrivateKey;

  // Exactly 3 lines so it fits in UIs that show only a few lines
  const out = (s) => process.stdout.write(s + "\n");
  out("Airlock pairing — enter this code in the app:");
  out(`>>> ${pairingCode6} <<<`);
  out("Waiting for pairing to complete...");
  logger(`Pairing code: ${pairingCode6}; waiting for completion.`);

  const deadline = Date.now() + 10 * 60 * 1000; // 10 min
  const pollInterval = 3000;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollInterval));

    const status = await pollPairingStatus(gatewayUrl, session.pairingNonce, token);
    if (status.state === "Expired") {
      throw new Error("Pairing session expired. Please run 'pair' again.");
    }
    if (status.state !== "Completed") {
      continue;
    }

    if (!status.responseJson || !status.routingToken) {
      throw new Error("Invalid pairing completion response");
    }

    const response = JSON.parse(status.responseJson);
    if (!verifyPairingResponse(response, logger)) {
      throw new Error("Pairing response signature verification failed");
    }

    let encryptionKey = null;
    if (response.x25519PublicKey && privateKey) {
      encryptionKey = deriveSharedKey(privateKey, response.x25519PublicKey);
    }
    if (!encryptionKey) {
      throw new Error("Could not derive encryption key (missing x25519 in response)");
    }

    const wsHash = config.computeWorkspaceHash(workspacePath || process.cwd());
    await config.storeRoutingTokenAsync(wsHash, status.routingToken);
    await config.storeEncryptionKeyAsync(wsHash, encryptionKey);
    await config.storePairedKeyAsync(
      wsHash,
      response.signerKeyId,
      response.publicKey,
      response.deviceId || "mobile"
    );

    logger("Pairing complete. Routing token and encryption key saved.");
    return true;
  }

  throw new Error("Pairing timed out. Please try again.");
}

module.exports = {
  getEnforcerId,
  DEVICE_ID,
  initiatePairing,
  pollPairingStatus,
  verifyPairingResponse,
  pair,
};
