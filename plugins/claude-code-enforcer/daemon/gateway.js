"use strict";

/**
 * Gateway: submit artifacts and poll for decisions. All HTTP is to the configured gateway base URL only.
 * Endpoints: POST /v1/artifacts, GET /v1/exchanges/:id/wait,
 *            POST /v1/exchanges/:id/withdraw, GET /v1/subscription/
 */
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const auth = require("./auth.js");
const config = require("./config.js");
const { encryptPayload } = require("./crypto.js");

const POLL_INTERVAL_SEC = 25;

function ensureGatewayOrigin(url, gatewayBase) {
  const u = String(url || "").trim();
  const base = String(gatewayBase || "").replace(/\/$/, "");
  if (!base) return;
  try {
    const parsed = new URL(u);
    const baseParsed = new URL(base);
    if (parsed.origin !== baseParsed.origin) {
      throw new Error(`Gateway: request URL must be on gateway origin (${baseParsed.origin}), got ${parsed.origin}`);
    }
  } catch (e) {
    if (e.message && e.message.startsWith("Gateway:")) throw e;
  }
}

function httpRequest(method, url, body, token, gatewayBase) {
  if (gatewayBase) ensureGatewayOrigin(url, gatewayBase);
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === "https:" ? https : http;
    const data = body ? JSON.stringify(body) : undefined;
    const headers = {};
    if (data) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(data);
    }
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const req = transport.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers,
        timeout: 650000,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk) => (raw += chunk));
        res.on("end", () => {
          if (res.statusCode === 204) {
            resolve({ status: 204, body: null });
            return;
          }
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ status: res.statusCode, body: raw });
            return;
          }
          resolve({ status: res.statusCode || 500, body: raw });
        });
      }
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

function parseErrorCode(body) {
  try {
    const o = JSON.parse(body || "{}");
    return (o.errorCode || o.code || o.error || "").toString();
  } catch {
    return "";
  }
}

/**
 * Check subscription/quota status. Non-fatal — returns null on failure.
 */
async function checkSubscription(gatewayUrl, token, log) {
  const base = gatewayUrl.replace(/\/$/, "");
  const url = `${base}/v1/subscription/`;
  try {
    const result = await httpRequest("GET", url, undefined, token, base);
    if (result.status >= 200 && result.status < 300 && result.body) {
      const data = JSON.parse(result.body);
      log(`Subscription: plan=${data.plan || "unknown"}, usage=${data.usageCount ?? "?"}/${data.limit ?? "?"}`);
      return data;
    }
    log(`Subscription check failed: HTTP ${result.status}`);
    return null;
  } catch (e) {
    log(`Subscription check error: ${e.message || e}`);
    return null;
  }
}

/**
 * Withdraw a pending exchange. Fire-and-forget — errors are logged but don't affect the caller.
 */
async function withdrawExchange(gatewayUrl, requestId, token, log) {
  const base = gatewayUrl.replace(/\/$/, "");
  const url = `${base}/v1/exchanges/${requestId}/withdraw`;
  try {
    await httpRequest("POST", url, undefined, token, base);
    log(`Exchange withdrawn: ${requestId}`);
  } catch (e) {
    log(`Withdraw failed (non-fatal): ${e.message || e}`);
  }
}

/**
 * Acknowledge receipt of a decision or artifact. Fire-and-forget safe.
 */
async function submitAck(gatewayUrl, msgId, requestId, token, log) {
  const base = gatewayUrl.replace(/\/$/, "");
  const url = `${base}/v1/acks`;
  const envelope = {
    msgId: `ack-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    msgType: "ack.submit",
    requestId: requestId || msgId,
    createdAt: new Date().toISOString(),
    sender: {},
    body: {
      msgId,
      status: "delivered",
      ackAt: new Date().toISOString(),
    },
  };
  try {
    await httpRequest("POST", url, envelope, token, base);
    log(`Ack submitted (status='delivered') for msgId=${msgId}`);
  } catch (e) {
    log(`Ack failed (non-fatal): ${e.message || e}`);
  }
}

function verifyDecisionSignature(
  wsHash,
  artifactHash,
  decision,
  nonce,
  signatureBase64Url,
  signerKeyId,
  log
) {
  const pairedKeys = config.getPairedKeys(wsHash);
  const keyEntry =
    pairedKeys[signerKeyId] ||
    pairedKeys[signerKeyId.replace(/^key-/, "")] ||
    pairedKeys[`key-${signerKeyId}`];
  if (!keyEntry) {
    log(`Unknown signerKeyId=${signerKeyId}`);
    return false;
  }

  let sigB64 = (signatureBase64Url || "").replace(/-/g, "+").replace(/_/g, "/");
  while (sigB64.length % 4 !== 0) sigB64 += "=";
  const signatureBytes = Buffer.from(sigB64, "base64");
  const canonical = `${artifactHash}|${decision}|${nonce}`;
  const message = Buffer.from(canonical, "utf-8");
  const publicKeyBytes = Buffer.from(keyEntry.publicKey, "base64");

  try {
    if (
      crypto.verify(
        null,
        message,
        { key: publicKeyBytes, format: "der", type: "spki" },
        signatureBytes
      )
    ) {
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
      return true;
    }
  } catch (_) {}
  return false;
}

function parseDecision(data, wsHash, log) {
  if (!data || typeof data !== "object") return null;
  const body = data.body || data;
  const dec = String(body.decision ?? body.Decision ?? "").toLowerCase();
  if (dec !== "approve" && dec !== "reject") return null;

  const signerKeyId = body.signerKeyId ?? body.SignerKeyId;
  const signature = body.signature ?? body.Signature;
  const nonce = body.nonce ?? body.Nonce;
  const artifactHash = body.artifactHash ?? body.ArtifactHash;

  if (signature && signerKeyId && nonce && artifactHash) {
    const verified = verifyDecisionSignature(
      wsHash,
      artifactHash,
      dec,
      nonce,
      signature,
      signerKeyId,
      log
    );
    if (!verified) {
      log("Decision signature verification failed");
      return null;
    }
  }

  return {
    decision: dec === "approve" ? "allow" : "deny",
    reason: body.reason ?? body.Reason,
  };
}

/**
 * Submit artifact and wait for decision. Returns { permission: "allow"|"deny", message?, agentMessage? }.
 */
async function requestApproval(opts, log) {
  const {
    gatewayUrl,
    actionType,
    commandText,
    buttonText,
    workspaceName,
    repoName,
    enforcerId,
    wsHash,
    timeoutSeconds = 120,
  } = opts;

  const token = await auth.ensureFreshToken();
  if (!token) {
    return { permission: "deny", message: "Not signed in", agentMessage: "Sign in first (run: login)." };
  }

  const routingToken = config.getRoutingToken(wsHash);
  if (!routingToken) {
    return { permission: "deny", message: "Not paired", agentMessage: "Pair your device first (run: pair)." };
  }

  const encryptionKey = config.getEncryptionKey(wsHash);
  if (!encryptionKey) {
    return { permission: "deny", message: "No encryption key", agentMessage: "Pair your device first (run: pair)." };
  }

  const requestId = "req-" + crypto.randomUUID();
  const msgId = "msg-" + crypto.randomUUID();
  const plaintextContent = JSON.stringify({
    actionType,
    commandText,
    description: buttonText,
    workspace: workspaceName,
    repoName: repoName || "",
    source: "claude-code-enforcer",
    extensions: {
      "org.harp.requestedActions": {
        version: 1,
        actions: [
          { id: "approve", caption: "Approve", style: "primary", decision: "approve" },
          { id: "reject", caption: "Reject", style: "danger", decision: "reject" },
        ],
      },
    },
  });

  const ciphertext = encryptPayload(plaintextContent, encryptionKey);
  const artifactHash = crypto
    .createHash("sha256")
    .update(`${actionType}:${commandText}:${Date.now()}`)
    .digest("hex");

  const envelope = {
    msgId,
    msgType: "artifact.submit",
    requestId,
    createdAt: new Date().toISOString(),
    sender: { enforcerId: enforcerId || "unknown" },
    body: {
      artifactType: "command.review",
      artifactHash,
      ciphertext,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      metadata: {
        repoName: repoName || "",
        workspaceName: workspaceName || "",
        requestLabel: actionType === "terminal_command" ? "Terminal Command" : "Agent Step",
        routingToken,
      },
    },
  };

  const gatewayBase = gatewayUrl.replace(/\/$/, "");
  const submitUrl = `${gatewayBase}/v1/artifacts`;
  let submitResult = await httpRequest("POST", submitUrl, envelope, token, gatewayBase);

  if (submitResult.status === 401) {
    const refreshed = await auth.refresh();
    if (refreshed) {
      const newToken = await auth.ensureFreshToken();
      submitResult = await httpRequest("POST", submitUrl, envelope, newToken, gatewayBase);
    }
  }

  if (submitResult.status === 403) {
    const errCode = parseErrorCode(submitResult.body);
    return {
      permission: "deny",
      message: `Access denied: ${errCode || "pairing revoked"}`,
      agentMessage: "Pairing may be revoked. Run 'pair' again.",
    };
  }
  if (submitResult.status === 429) {
    return {
      permission: "deny",
      message: "Quota exceeded",
      agentMessage: "Airlock quota exceeded. Try again later.",
    };
  }
  if (submitResult.status < 200 || submitResult.status >= 300) {
    // Withdraw in case the exchange was partially created
    withdrawExchange(gatewayBase, requestId, token, log).catch(() => {});
    return {
      permission: "deny",
      message: `Gateway error: ${submitResult.status}`,
      agentMessage: `Gateway returned ${submitResult.status}. Check gateway URL and connectivity.`,
    };
  }

  // Successfully submitted artifact to exchange. Submit ack to transition to Delivered status.
  submitAck(gatewayBase, msgId, requestId, token, log).catch(() => {});

  const deadline = Date.now() + timeoutSeconds * 1000;
  let pollCount = 0;

  while (Date.now() < deadline) {
    pollCount++;
    const remainingSec = Math.ceil((deadline - Date.now()) / 1000);
    const serverTimeout = Math.min(POLL_INTERVAL_SEC, remainingSec);
    if (serverTimeout <= 0) break;

    const waitUrl = `${gatewayBase}/v1/exchanges/${requestId}/wait?timeout=${serverTimeout}`;
    const freshToken = await auth.ensureFreshToken() || token;

    try {
      const waitResult = await httpRequest("GET", waitUrl, undefined, freshToken, gatewayBase);
      if (waitResult.status === 204 || !waitResult.body) {
        continue;
      }
      if (waitResult.status >= 200 && waitResult.status < 300 && waitResult.body) {
        const parsed = JSON.parse(waitResult.body);
        const decision = parseDecision(parsed, wsHash, log);
        if (decision) {
          const agentMessage =
            decision.decision === "deny"
              ? (decision.reason || "Action denied by approver.")
              : undefined;
          return {
            permission: decision.decision,
            message: decision.reason,
            agentMessage,
          };
        }
      }
    } catch (e) {
      log(`Poll error: ${e.message}`);
    }
  }

  // Withdraw stale exchange so it doesn't clutter mobile inbox
  withdrawExchange(gatewayBase, requestId, token, log).catch(() => {});
  return {
    permission: "deny",
    message: "Approval timed out",
    agentMessage: "Airlock approval timed out. The action was blocked.",
  };
}

module.exports = {
  requestApproval,
  parseErrorCode,
  checkSubscription,
  withdrawExchange,
};
