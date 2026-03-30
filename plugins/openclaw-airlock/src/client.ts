/**
 * Airlock Client — wraps @airlockapp/gateway-sdk with approval workflow logic.
 *
 * Responsibilities:
 * - Submit encrypted artifacts for approval
 * - Poll for decisions (long-poll with server-side 25s timeout)
 * - Verify decision signatures (Ed25519)
 * - Claim pre-generated pairing codes (X25519 ECDH key exchange)
 * - Persist pairing state to disk
 * - Health check via gateway echo
 * - Presence heartbeat
 * - DND (Do Not Disturb) policy check
 * - Handle HTTP errors (401, 403, 422, 429) with appropriate responses
 */

import {
  AirlockGatewayClient,
  AirlockGatewayError,
} from "@airlockapp/gateway-sdk";
import type {
  DecisionDeliverEnvelope,
  EchoResponse,
} from "@airlockapp/gateway-sdk";
import type { AirlockConfig } from "./config.js";
import {
  generateX25519KeyPair,
  deriveSharedKey,
  verifyDecisionSignature,
  type PairedKeyEntry,
} from "./crypto.js";
import {
  loadPairingState,
  savePairingState,
  clearPairingState,
  loadPairedKeys,
} from "./state.js";

// ── Types ───────────────────────────────────────────────────────

/** Payload for an approval request. */
export interface ApprovalPayload {
  /** Tool name or action type (e.g. "shell.exec", "deploy.run"). */
  actionType: string;
  /** The command or action text to display to the approver. */
  commandText: string;
  /** Human-readable description for the approval card. */
  description: string;
  /** Optional additional context. */
  context?: string;
}

/** Approval decision returned by the client. */
export interface Decision {
  /** The decision result. */
  decision: "approved" | "rejected" | "timeout";
  /** Optional reason from the approver. */
  reason?: string;
  /** The exchange request ID. */
  requestId: string;
}

/** Gateway health check result. */
export interface HealthResult {
  connected: boolean;
  gatewayUrl: string;
  serverTime?: string;
  error?: string;
}

// ── Constants ───────────────────────────────────────────────────

/** Server-side long-poll timeout per request (seconds). */
const LONG_POLL_TIMEOUT_SEC = 25;

/** Source identifier sent in artifact metadata. */
const SOURCE_ID = "openclaw-airlock";

/** Presence heartbeat interval (ms). */
const HEARTBEAT_INTERVAL_MS = 45_000;

// ── Client ──────────────────────────────────────────────────────

export class AirlockClient {
  private readonly gateway: AirlockGatewayClient;
  private readonly config: AirlockConfig;
  private readonly log: (msg: string) => void;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private pairedKeys: Record<string, PairedKeyEntry> = {};

  constructor(config: AirlockConfig, logger?: (msg: string) => void) {
    this.config = config;
    this.log = logger ?? ((msg: string) => console.error(`[Airlock] ${msg}`));

    this.gateway = new AirlockGatewayClient({
      baseUrl: config.gatewayUrl,
      pat: config.pat,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
    });
  }

  // ── Initialization ────────────────────────────────────────────

  /**
   * Restore pairing state from disk and start presence heartbeat.
   * Call this after creating the client.
   */
  async initialize(): Promise<void> {
    // Restore persisted pairing state
    const state = await loadPairingState();
    if (state) {
      this.config.routingToken = state.routingToken;
      this.config.encryptionKey = state.encryptionKey;
      this.pairedKeys = state.pairedKeys;
      this.log("Pairing state restored from disk");
    }

    // Start presence heartbeat
    this.startHeartbeat();
  }

  /** Stop background tasks (heartbeat timer). */
  dispose(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  // ── Approval Flow ─────────────────────────────────────────────

  /**
   * Submit an encrypted artifact for approval and poll for the decision.
   * Returns when the approver decides or the timeout elapses.
   */
  async requestApproval(payload: ApprovalPayload): Promise<Decision> {
    if (!this.config.encryptionKey) {
      return {
        decision: "rejected",
        reason: "Not paired — run 'airlock pair' first",
        requestId: "",
      };
    }

    if (!this.config.routingToken) {
      return {
        decision: "rejected",
        reason: "No routing token — run 'airlock pair' first",
        requestId: "",
      };
    }

    // Build plaintext payload with HARP requestedActions extension
    const plaintextPayload = JSON.stringify({
      actionType: payload.actionType,
      commandText: payload.commandText,
      description: payload.description,
      context: payload.context ?? "",
      workspace: this.config.workspaceName,
      source: SOURCE_ID,
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

    let requestId: string;
    try {
      requestId = await this.gateway.encryptAndSubmitArtifact({
        enforcerId: this.config.enforcerId,
        artifactType: "command.review",
        plaintextPayload,
        encryptionKeyBase64Url: this.config.encryptionKey,
        metadata: {
          workspaceName: this.config.workspaceName,
          routingToken: this.config.routingToken,
          requestLabel: payload.actionType === "terminal_command" ? "Terminal Command" : "Agent Action",
        },
      });
    } catch (err) {
      return await this.handleSubmitError(err);
    }

    this.log(`Artifact submitted: ${requestId}`);

    // Submit ack (fire-and-forget)
    this.gateway.submitAck(`msg-${requestId}`, requestId).catch(() => {});

    return this.pollDecision(requestId);
  }

  /**
   * Poll for a decision using the long-poll endpoint.
   * Repeats until the decision is received or timeout elapses.
   */
  private async pollDecision(requestId: string): Promise<Decision> {
    const deadline = Date.now() + this.config.timeoutMs;
    let pollCount = 0;

    while (Date.now() < deadline) {
      pollCount++;
      const remainingSec = Math.ceil((deadline - Date.now()) / 1000);
      const serverTimeout = Math.min(LONG_POLL_TIMEOUT_SEC, remainingSec);
      if (serverTimeout <= 0) break;

      try {
        const envelope = await this.gateway.waitForDecision(requestId, serverTimeout);

        if (!envelope) {
          // 204 — no decision yet, continue polling
          continue;
        }

        const decision = this.parseDecision(envelope, requestId);
        if (decision) return decision;
      } catch (err) {
        if (err instanceof AirlockGatewayError) {
          if (err.statusCode === 401) {
            this.log("Received 401 during poll — retrying");
            continue;
          }
          this.log(`Poll error (HTTP ${err.statusCode}): ${err.message}`);
        } else {
          this.log(`Poll error: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    // Timed out — withdraw the stale exchange
    this.log(`Approval timed out after ${this.config.timeoutMs}ms (${pollCount} polls)`);
    this.gateway.withdrawExchange(requestId).catch(() => {});

    return { decision: "timeout", requestId };
  }

  // ── DND Policy Check ──────────────────────────────────────────

  /**
   * Check if a DND (Do Not Disturb) policy is active that would auto-approve
   * actions for the current enforcer/workspace.
   *
   * @returns True if a matching DND policy covers this action (auto-approve).
   */
  async isDndActive(): Promise<boolean> {
    try {
      const resp = await this.gateway.getEffectiveDndPolicies(
        this.config.enforcerId,
        this.config.enforcerId, // workspaceId = enforcerId for now
      );
      if (resp.body && resp.body.length > 0) {
        this.log(`DND active: ${resp.body.length} policy/policies`);
        return true;
      }
      return false;
    } catch {
      // DND check is best-effort — if it fails, proceed to normal approval
      return false;
    }
  }

  // ── Health Check ──────────────────────────────────────────────

  /** Check gateway connectivity via the echo endpoint. */
  async checkHealth(): Promise<HealthResult> {
    try {
      const echo: EchoResponse = await this.gateway.echo();
      return {
        connected: true,
        gatewayUrl: this.config.gatewayUrl,
        serverTime: echo.utc,
      };
    } catch (err) {
      return {
        connected: false,
        gatewayUrl: this.config.gatewayUrl,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  // ── Exchange Status ───────────────────────────────────────────

  /**
   * Get the status of an exchange by request ID.
   * Returns the exchange state (Pending, Decided, Expired, Withdrawn).
   */
  async getExchangeStatus(requestId: string): Promise<{
    state: string;
    createdAt?: string;
    expiresAt?: string;
  }> {
    const resp = await this.gateway.getExchangeStatus(requestId);
    return {
      state: resp.body?.state ?? "unknown",
      createdAt: resp.body?.createdAt,
      expiresAt: resp.body?.expiresAt,
    };
  }

  // ── Presence Heartbeat ────────────────────────────────────────

  /** Start periodic presence heartbeat so the mobile app shows enforcer online. */
  private startHeartbeat(): void {
    if (this.heartbeatTimer) return;

    const sendHeartbeat = () => {
      this.gateway.sendHeartbeat({
        enforcerId: this.config.enforcerId,
        workspaceName: this.config.workspaceName,
        enforcerLabel: "OpenClaw",
      }).catch(() => {
        // Heartbeat is best-effort
      });
    };

    // Send immediately on start, then at intervals
    sendHeartbeat();
    this.heartbeatTimer = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL_MS);

    // Prevent the timer from blocking Node.js exit
    if (this.heartbeatTimer && typeof this.heartbeatTimer === "object" && "unref" in this.heartbeatTimer) {
      this.heartbeatTimer.unref();
    }
  }

  // ── Pairing ───────────────────────────────────────────────────

  /**
   * Claim a pre-generated pairing code with proper X25519 ECDH key exchange.
   * Polls until pairing is completed, derives shared encryption key,
   * and persists the pairing state to disk.
   *
   * @param code The pre-generated pairing code.
   * @returns Routing token and encryption key for artifact encryption.
   */
  async claimPairing(code: string): Promise<{
    routingToken: string;
    encryptionKey: string;
    pairingNonce: string;
  }> {
    const { randomUUID } = await import("node:crypto");
    const deviceId = `openclaw-${randomUUID().slice(0, 8)}`;

    // Generate X25519 keypair for ECDH key exchange
    const keyPair = generateX25519KeyPair();

    this.log(`Claiming pairing code: ${code}`);

    const claim = await this.gateway.claimPairing({
      pairingCode: code,
      deviceId,
      enforcerId: this.config.enforcerId,
      enforcerLabel: "OpenClaw",
      workspaceName: this.config.workspaceName,
      x25519PublicKey: keyPair.publicKey,
    });

    this.log(`Pairing initiated: nonce=${claim.pairingNonce}, expires=${claim.expiresAt}`);

    // Poll for completion
    const deadline = Date.now() + 10 * 60 * 1000; // 10 min
    const pollInterval = 3000;

    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, pollInterval));

      const status = await this.gateway.getPairingStatus(claim.pairingNonce);

      if (status.state === "Expired") {
        throw new Error("Pairing code expired. Generate a new one and try again.");
      }

      if (status.state !== "Completed") {
        continue;
      }

      if (!status.routingToken || !status.responseJson) {
        throw new Error("Invalid pairing completion response — missing routing token or response data");
      }

      // Parse the pairing response to get the approver's X25519 public key
      const response = JSON.parse(status.responseJson);

      // Derive shared encryption key via X25519 ECDH
      if (!response.x25519PublicKey) {
        throw new Error("Pairing response missing x25519PublicKey — cannot derive encryption key");
      }

      const encryptionKey = deriveSharedKey(keyPair.privateKey, response.x25519PublicKey);

      // Store the approver's Ed25519 signing key for decision verification
      const pairedKeys: Record<string, PairedKeyEntry> = {};
      if (response.signerKeyId && response.publicKey) {
        pairedKeys[response.signerKeyId] = {
          publicKey: response.publicKey,
          deviceId: response.deviceId ?? "mobile",
        };
      }

      // Update runtime state
      this.config.routingToken = status.routingToken;
      this.config.encryptionKey = encryptionKey;
      this.pairedKeys = pairedKeys;

      // Persist state to disk
      await savePairingState({
        routingToken: status.routingToken,
        encryptionKey,
        pairedKeys,
        pairedAt: new Date().toISOString(),
        pairingNonce: claim.pairingNonce,
      });

      this.log("Pairing completed — keys derived and persisted");

      return {
        routingToken: status.routingToken,
        encryptionKey,
        pairingNonce: claim.pairingNonce,
      };
    }

    throw new Error("Pairing timed out (10 minutes). Try again.");
  }

  // ── Helpers ───────────────────────────────────────────────────

  private parseDecision(
    envelope: DecisionDeliverEnvelope,
    requestId: string,
  ): Decision | null {
    const body = envelope.body;
    if (!body) return null;

    const dec = String(body.decision ?? "").toLowerCase();
    if (dec !== "approve" && dec !== "reject") return null;

    // Verify decision signature if signing material is present
    const signerKeyId = body.signerKeyId;
    const signature = body.signature;
    const nonce = body.nonce;
    const artifactHash = body.artifactHash;

    if (signature && signerKeyId && nonce && artifactHash) {
      const verified = verifyDecisionSignature(
        this.pairedKeys,
        artifactHash,
        dec,
        nonce,
        signature,
        signerKeyId,
      );
      if (!verified) {
        this.log(`Decision signature verification failed for signerKeyId=${signerKeyId}`);
        return null; // Reject unverifiable decisions
      }
      this.log("Decision signature verified ✓");
    }

    return {
      decision: dec === "approve" ? "approved" : "rejected",
      reason: body.reason,
      requestId,
    };
  }

  private async handleSubmitError(err: unknown): Promise<Decision> {
    if (err instanceof AirlockGatewayError) {
      // 403 — pairing revoked or access denied
      if (err.statusCode === 403) {
        const code = err.errorCode ?? "";
        if (code === "pairing_revoked" || code === "no_approver") {
          await this.clearPairingState();
        }
        return {
          decision: "rejected",
          reason: `Access denied: ${code || "forbidden"} — run 'airlock pair' again`,
          requestId: "",
        };
      }

      // 422 — validation error (may include no_approver)
      if (err.statusCode === 422) {
        const code = err.errorCode ?? "";
        if (code === "no_approver") {
          await this.clearPairingState();
          return {
            decision: "rejected",
            reason: "No approver available — pairing may be stale. Run 'airlock pair' again.",
            requestId: "",
          };
        }
        return {
          decision: "rejected",
          reason: `Validation error: ${err.message}`,
          requestId: "",
        };
      }

      // 429 — quota exceeded
      if (err.statusCode === 429) {
        return {
          decision: "rejected",
          reason: "Quota exceeded — try again later",
          requestId: "",
        };
      }
    }

    const msg = err instanceof Error ? err.message : String(err);
    return {
      decision: "rejected",
      reason: `Gateway error: ${msg}`,
      requestId: "",
    };
  }

  /** Clear pairing state from memory and disk. */
  private async clearPairingState(): Promise<void> {
    this.config.routingToken = undefined;
    this.config.encryptionKey = undefined;
    this.pairedKeys = {};
    await clearPairingState().catch(() => {});
    this.log("Pairing state cleared (revoked or stale)");
  }
}

/** Factory function to create an AirlockClient from validated config. */
export function createAirlockClient(
  config: AirlockConfig,
  logger?: (msg: string) => void,
): AirlockClient {
  return new AirlockClient(config, logger);
}
