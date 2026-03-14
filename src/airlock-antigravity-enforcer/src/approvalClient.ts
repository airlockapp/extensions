import * as vscode from "vscode";
import * as http from "http";
import * as https from "https";
import * as crypto from "crypto";
import { encryptPayload, getEncryptionKey, getRoutingToken, clearRoutingToken, type EncryptedPayload } from "./crypto.js";
import { getPairedKeys } from "./pairingClient.js";
import { evaluateDndForAction } from "./dndClient.js";

export interface ApprovalResult {
    decision: "approve" | "reject";
    reason?: string;
    requestId: string;
}

/**
 * Thrown when the gateway returns a quota-related error (429 or 403 with quota error code).
 * Callers should treat this as fail-open — the developer should not be blocked.
 */
export class QuotaExceededError extends Error {
    constructor(public readonly statusCode: number, public readonly errorCode: string, message: string) {
        super(message);
        this.name = "QuotaExceededError";
    }
}

/**
 * Submit an artifact for approval via the existing HARP Gateway flow:
 *   1. POST /v1/artifacts  — create exchange + push to approver inbox
 *   2. GET  /v1/exchanges/{requestId}/wait — long-poll until decision
 *
 * Returns the decision (approve/reject).
 */
export async function requestApproval(
    endpointUrl: string,
    actionType: string,
    commandText: string,
    buttonText: string,
    out: vscode.OutputChannel,
    timeoutSeconds: number = 600,
    context?: vscode.ExtensionContext,
    externalRequestId?: string,
    abortSignal?: AbortSignal,
    authToken?: string,
    diagnosticMode: boolean = false,
    onTokenRefresh?: () => Promise<void>
): Promise<ApprovalResult> {
    const ws = vscode.workspace.workspaceFolders?.[0];
    const requestId = externalRequestId ?? "req-" + crypto.randomUUID();
    const msgId = "msg-" + crypto.randomUUID();
    const submitStartTime = Date.now();

    out.appendLine(`[Airlock] 📤 Approval request: ${actionType} (timeout=${timeoutSeconds}s)`);
    if (diagnosticMode) {
        out.appendLine(`[Airlock] ──────────────────────────────────────────`);
        out.appendLine(`[Airlock]   requestId: ${requestId}`);
        out.appendLine(`[Airlock]   msgId: ${msgId}`);
        out.appendLine(`[Airlock]   actionType: ${actionType}`);
        out.appendLine(`[Airlock]   commandText: ${commandText.substring(0, 200)}${commandText.length > 200 ? '...' : ''}`);
        out.appendLine(`[Airlock]   buttonText: ${buttonText.substring(0, 200)}${buttonText.length > 200 ? '...' : ''}`);
        out.appendLine(`[Airlock]   timeout: ${timeoutSeconds}s`);
    }

    // Build HARP artifact.submit envelope
    const workspaceName = ws?.name || "unknown";

    // Before building the artifact, check effective DND policies for this action.
    const enforcerId =
        context?.workspaceState.get<string>("airlock.enforcerId")
        || vscode.workspace.getConfiguration("airlock").get<string>("enforcerId")
        || "enforcer-vscode";

    const dndMatch = await evaluateDndForAction(
        {
            endpointUrl,
            workspaceId: workspaceName,
            enforcerId,
            sessionId: vscode.env.sessionId,
            authToken,
        },
        {
            actionType,
            commandText,
        },
        diagnosticMode ? out : undefined
    );

    if (dndMatch) {
        const isApprove = dndMatch.decision === "approve";

        out.appendLine(
            `[Airlock] DND in effect: ${dndMatch.scope} policy (${dndMatch.policyMode}) → ${isApprove ? "APPROVE" : "REJECT"}`
        );

        // Fire-and-forget audit artifact so mobile can see bypassed commands
        // via the Gateway's DND audit path.
        submitDndAuditArtifact(
            endpointUrl,
            workspaceName,
            enforcerId,
            actionType,
            commandText,
            buttonText,
            authToken,
            context
        ).catch(() => { /* non-fatal */ });

        return {
            decision: isApprove ? "approve" : "reject",
            reason: "Decision from Do Not Disturb policy",
            requestId,
        };
    } else if (diagnosticMode) {
        out.appendLine("[Airlock] DND: no matching policy for this action");
    }

    // Sensitive display data — goes INSIDE encrypted ciphertext, NOT in cleartext metadata
    const plaintextContent = JSON.stringify({
        actionType,
        commandText,
        buttonText,
        workspace: workspaceName,
        repoName: "",
        source: "antigravity-enforcer",
    });

    // HARP-GW §2.1: Gateway is zero-knowledge — artifacts MUST be encrypted
    const encryptionKey = context ? await getEncryptionKey(context) : null;
    if (!encryptionKey) {
        out.appendLine("[Airlock] ✗ No encryption key — cannot submit artifact (pair device first)");
        vscode.window.showWarningMessage(
            "Airlock: Cannot submit — no encryption key. Please pair your mobile device first.",
            "Pair Now"
        ).then(choice => {
            if (choice === "Pair Now") {
                vscode.commands.executeCommand("airlock.startPairing");
            }
        });
        throw new Error("No encryption key available — pair your mobile device to enable E2E encryption");
    }

    const ciphertext: EncryptedPayload = encryptPayload(plaintextContent, encryptionKey);
    if (diagnosticMode) { out.appendLine("[Airlock]   encryption: AES-256-GCM ✓"); }

    const routingToken = context ? getRoutingToken(context) : null;
    const metadata: Record<string, string> = {};

    if (routingToken) {
        metadata.routingToken = routingToken;
        if (diagnosticMode) { out.appendLine(`[Airlock]   routing: opaque token (${routingToken.length} chars)`); }
    } else {
        const approverId = vscode.workspace.getConfiguration("airlock").get<string>("approverId");
        if (approverId) {
            metadata.approverId = approverId;
            if (diagnosticMode) { out.appendLine(`[Airlock]   routing: approverId=${approverId}`); }
        } else {
            out.appendLine(`[Airlock]   routing: NONE ⚠ (no routing token or approverId)`);
        }
    }

    // Workspace identity — cleartext so the mobile app can group items by workspace
    metadata.repoName = "";
    metadata.workspaceName = workspaceName;
    if (diagnosticMode) { out.appendLine(`[Airlock]   workspace: ${workspaceName}`); }

    const artifactBody = {
        artifactType: "command-approval",
        artifactHash: crypto.createHash("sha256")
            .update(`${actionType}:${commandText}:${Date.now()}`)
            .digest("hex"),
        ciphertext,
        // Artifact stays in inbox for 10 minutes (review window)
        expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        // Metadata: ONLY routing-critical fields — opaque token or approverId, tenantId
        metadata,
    };

    const envelope = {
        msgId,
        msgType: "artifact.submit",
        requestId,
        createdAt: new Date().toISOString(),
            sender: {
                enforcerId,
        },
        body: artifactBody,
    };

    // Step 1: Submit artifact
    const submitUrl = `${endpointUrl}/v1/artifacts`;
    const artifactHash = (envelope.body as Record<string, unknown>).artifactHash as string;
    if (diagnosticMode) {
        out.appendLine(`[Airlock] 📡 POST ${submitUrl}`);
        out.appendLine(`[Airlock]   artifactHash: ${artifactHash}`);
    }

    try {
        const submitResult = await httpRequest("POST", submitUrl, envelope, undefined, authToken);
        const submitElapsed = Date.now() - submitStartTime;
        out.appendLine(`[Airlock] ✓ Artifact accepted (${submitElapsed}ms)`);
        out.appendLine(`[Airlock]   requestId: ${requestId}`);
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        const submitElapsed = Date.now() - submitStartTime;

        // 401 retry: refresh token and retry once
        if (msg.includes("HTTP 401") && onTokenRefresh) {
            out.appendLine(`[Airlock] ⚠ 401 on submit (${submitElapsed}ms) — refreshing token and retrying...`);
            try {
                await onTokenRefresh();
                const retryResult = await httpRequest("POST", submitUrl, envelope, undefined, authToken);
                const retryElapsed = Date.now() - submitStartTime;
                out.appendLine(`[Airlock] ✓ Artifact accepted after token refresh (${retryElapsed}ms)`);
                out.appendLine(`[Airlock]   requestId: ${requestId}`);
            } catch (retryErr: unknown) {
                const retryMsg = retryErr instanceof Error ? retryErr.message : String(retryErr);
                out.appendLine(`[Airlock] ✗ Retry after refresh also failed: ${retryMsg}`);
                throw retryErr;
            }
        } else {
            out.appendLine(`[Airlock] ✗ Artifact submit FAILED (${submitElapsed}ms): ${msg}`);

            // Detect stale routing token / no approver
            if (msg.includes("no_approver") || msg.includes("422")) {
                out.appendLine(`[Airlock] ⚠ Routing token may be stale — clearing and prompting re-pair`);
                if (context) {
                    await clearRoutingToken(context);
                }
                vscode.window.showWarningMessage(
                    "Airlock: No approver found — your pairing may be stale. Please re-pair with your mobile device.",
                    "Pair Now"
                ).then(choice => {
                    if (choice === "Pair Now") {
                        vscode.commands.executeCommand("airlock.startPairing");
                    }
                });
            }

            throw err;
        }
    }

    // Step 2: Long-poll for decision (use 25s server-side intervals for retries)
    const pollIntervalSec = 25;
    const deadline = Date.now() + timeoutSeconds * 1000;
    let pollCount = 0;
    out.appendLine(`[Airlock] ⏳ Waiting for mobile decision (deadline: ${timeoutSeconds}s)...`);

    while (Date.now() < deadline) {
        pollCount++;
        const elapsedSec = Math.ceil((Date.now() - submitStartTime) / 1000);
        const remainingSec = Math.ceil((deadline - Date.now()) / 1000);
        const serverTimeout = Math.min(pollIntervalSec, remainingSec);
        if (serverTimeout <= 0) break;

        const waitUrl = `${endpointUrl}/v1/exchanges/${requestId}/wait?timeout=${serverTimeout}`;
        out.appendLine(`[Airlock] Poll #${pollCount}: elapsed=${elapsedSec}s, remaining=${remainingSec}s, serverWait=${serverTimeout}s`);

        // Check if aborted between polls
        if (abortSignal?.aborted) {
            throw new Error("Approval aborted — manual action detected");
        }

        try {
            const pollStart = Date.now();
            const waitResult = await httpRequest("GET", waitUrl, undefined, abortSignal, authToken);
            const pollDuration = Date.now() - pollStart;

            if (!waitResult) {
                out.appendLine(`[Airlock] Poll #${pollCount}: 204 No Content (${pollDuration}ms) — no decision yet`);
                continue;
            }

            out.appendLine(`[Airlock] Poll #${pollCount}: response received (${pollDuration}ms)`);

            // Parse decision.deliver response
            const decision = parseDecision(waitResult, context, out);
            if (decision) {
                const totalElapsed = Date.now() - submitStartTime;
                out.appendLine(`[Airlock] ──────────────────────────────────────────`);
                out.appendLine(`[Airlock] ${decision.decision === 'approve' ? '✅' : '❌'} DECISION: ${decision.decision.toUpperCase()}`);
                out.appendLine(`[Airlock]   requestId: ${requestId}`);
                out.appendLine(`[Airlock]   reason: ${decision.reason || '(none)'}`);
                out.appendLine(`[Airlock]   totalTime: ${totalElapsed}ms (${Math.ceil(totalElapsed / 1000)}s)`);
                out.appendLine(`[Airlock]   polls: ${pollCount}`);
                out.appendLine(`[Airlock] ──────────────────────────────────────────`);
                return { ...decision, requestId };
            }

            // Unknown response — keep polling
            out.appendLine(`[Airlock] Poll #${pollCount}: unexpected response format, retrying...`);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            if (Date.now() < deadline) {
                out.appendLine(`[Airlock] Poll #${pollCount} ERROR (retrying): ${msg}`);
                await sleep(1000);
            } else {
                throw err;
            }
        }
    }

    const totalElapsed = Date.now() - submitStartTime;
    out.appendLine(`[Airlock] ──────────────────────────────────────────`);
    out.appendLine(`[Airlock] ⏰ TIMEOUT: No decision received after ${Math.ceil(totalElapsed / 1000)}s (${pollCount} polls)`);
    out.appendLine(`[Airlock]   requestId: ${requestId}`);
    out.appendLine(`[Airlock] ──────────────────────────────────────────`);
    throw new Error("Approval timeout — no decision received");
}

function parseDecision(
    data: unknown,
    context?: vscode.ExtensionContext,
    out?: vscode.OutputChannel
): { decision: "approve" | "reject"; reason?: string } | null {
    if (!data || typeof data !== "object") return null;
    const obj = data as Record<string, unknown>;

    // decision.deliver envelope: body contains { decision, reason, signature, ... }
    const body = obj.body as Record<string, unknown> | undefined;
    if (!body) return null;

    const dec = String(body.decision ?? body.Decision ?? "").toLowerCase();
    if (dec !== "approve" && dec !== "reject") return null;

    // HARP-CORE §6.3: HE MUST verify Ed25519 signature over DecisionSignable canonical bytes
    const signerKeyId = body.signerKeyId as string | undefined ?? body.SignerKeyId as string | undefined;
    const signature = body.signature as string | undefined ?? body.Signature as string | undefined;
    const nonce = body.nonce as string | undefined ?? body.Nonce as string | undefined;
    const artifactHash = body.artifactHash as string | undefined ?? body.ArtifactHash as string | undefined;

    if (signature && signerKeyId && nonce && artifactHash && context) {
        const verified = verifyDecisionSignature(
            artifactHash, dec, nonce, signature, signerKeyId, context, out
        );
        if (!verified) {
            out?.appendLine(`[Airlock] ✗ HARP_ERR_SIGNATURE_INVALID: Decision signature verification FAILED for signerKeyId=${signerKeyId}`);
            return null; // Reject decision per HARP-CORE §6.3
        }
        out?.appendLine(`[Airlock] ✓ Decision signature verified for signerKeyId=${signerKeyId}`);
    } else if (context) {
        // Signature fields missing — reject per HARP-CORE §6.3
        out?.appendLine(`[Airlock] ✗ HARP_ERR_MISSING_SIGNATURE: Decision missing required signature fields`);
        return null;
    }
    // If no context available, allow through (legacy/testing mode) with warning

    return {
        decision: dec as "approve" | "reject",
        reason: body.reason as string | undefined ?? body.Reason as string | undefined,
    };
}

/**
 * Verify an Ed25519 decision signature per HARP-CORE §6.3.
 *
 * The mobile app signs: canonical = "artifactHash|decision|nonce"
 * Signature is base64url-encoded 64-byte Ed25519.
 * Public key is looked up from paired keys by signerKeyId.
 */
function verifyDecisionSignature(
    artifactHash: string,
    decision: string,
    nonce: string,
    signatureBase64Url: string,
    signerKeyId: string,
    context: vscode.ExtensionContext,
    out?: vscode.OutputChannel
): boolean {
    // Look up paired public key by signerKeyId (normalize 'key-' prefix)
    const pairedKeys = getPairedKeys(context);
    const keyEntry = pairedKeys[signerKeyId]
        ?? pairedKeys[signerKeyId.replace(/^key-/, "")]   // try without prefix
        ?? pairedKeys[`key-${signerKeyId}`];               // try with prefix
    if (!keyEntry) {
        out?.appendLine(`[Airlock] ✗ Unknown signerKeyId=${signerKeyId} — not in paired keys (have: ${Object.keys(pairedKeys).join(", ")})`);
        return false;
    }

    const publicKeyBase64 = keyEntry.publicKey;
    const publicKeyBytes = Buffer.from(publicKeyBase64, "base64");

    // Decode base64url signature — normalize to standard base64 with padding
    let sigB64 = signatureBase64Url.replace(/-/g, "+").replace(/_/g, "/");
    while (sigB64.length % 4 !== 0) { sigB64 += "="; }
    const signatureBytes = Buffer.from(sigB64, "base64");

    // Build canonical decision payload: "artifactHash|decision|nonce"
    const canonical = `${artifactHash}|${decision}|${nonce}`;
    const message = Buffer.from(canonical, "utf-8");

    // Attempt 1: direct DER/SPKI key (if publicKey is already in DER format)
    try {
        if (crypto.verify(null, message, {
            key: publicKeyBytes,
            format: "der",
            type: "spki"
        }, signatureBytes)) {
            return true;
        }
    } catch {
        // Not in DER/SPKI format, try raw
    }

    // Attempt 2: raw 32-byte Ed25519 key wrapped with SPKI DER prefix
    try {
        const keyObj = crypto.createPublicKey({
            key: Buffer.concat([
                Buffer.from("302a300506032b6570032100", "hex"),
                publicKeyBytes
            ]),
            format: "der",
            type: "spki"
        });
        if (crypto.verify(null, message, keyObj, signatureBytes)) {
            return true;
        }
    } catch {
        // Verification failed
    }

    return false;
}

/**
 * HTTP(S) request. Returns parsed JSON body or null for 204.
 */
function httpRequest(method: string, url: string, body?: object, abortSignal?: AbortSignal, authToken?: string): Promise<unknown> {
    return new Promise((resolve, reject) => {
        if (abortSignal?.aborted) {
            reject(new Error("Aborted"));
            return;
        }

        const data = body ? JSON.stringify(body) : undefined;
        const parsed = new URL(url);
        const transport = parsed.protocol === "https:" ? https : http;

        const reqHeaders: Record<string, string | number> = {};
        if (data) {
            reqHeaders["Content-Type"] = "application/json";
            reqHeaders["Content-Length"] = Buffer.byteLength(data);
        }
        if (authToken) {
            reqHeaders["Authorization"] = `Bearer ${authToken}`;
        }

        const req = transport.request(
            {
                hostname: parsed.hostname,
                port: parsed.port,
                path: parsed.pathname + parsed.search,
                method,
                headers: reqHeaders,
                timeout: 650_000, // slightly over max poll window (10 min)
            },
            (res) => {
                let responseData = "";
                res.on("data", (chunk) => (responseData += chunk));
                res.on("end", () => {
                    if (res.statusCode === 204) {
                        resolve(null);
                        return;
                    }
                    if (
                        res.statusCode !== undefined &&
                        res.statusCode >= 200 &&
                        res.statusCode < 300
                    ) {
                        try {
                            resolve(JSON.parse(responseData));
                        } catch {
                            reject(new Error("Invalid JSON response"));
                        }
                    } else {
                        // Detect quota-related errors → throw QuotaExceededError for fail-open
                        const QUOTA_ERROR_CODES = ["quota_exceeded", "workspace_limit_reached", "approver_limit_reached"];
                        if (res.statusCode === 429 || res.statusCode === 403) {
                            try {
                                const errBody = JSON.parse(responseData);
                                const errorCode = errBody?.error || "";
                                if (res.statusCode === 429 || QUOTA_ERROR_CODES.includes(errorCode)) {
                                    reject(new QuotaExceededError(
                                        res.statusCode!,
                                        errorCode || "quota_exceeded",
                                        `Quota exceeded (${errorCode}): ${responseData.slice(0, 200)}`
                                    ));
                                    return;
                                }
                            } catch { /* not JSON, fall through to generic error */ }
                        }
                        reject(
                            new Error(`HTTP ${res.statusCode}: ${responseData.slice(0, 200)}`)
                        );
                    }
                });
            }
        );

        req.on("timeout", () => {
            req.destroy();
            reject(new Error("Request timed out"));
        });
        req.on("error", reject);

        // Wire up abort signal
        if (abortSignal) {
            const onAbort = () => { req.destroy(new Error("Aborted")); };
            abortSignal.addEventListener("abort", onAbort, { once: true });
            req.on("close", () => abortSignal.removeEventListener("abort", onAbort));
        }

        if (data) req.write(data);
        req.end();
    });
}

function sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
}

/**
 * Submit a short-lived audit artifact for DND-bypassed commands so they are
 * visible in the mobile app's history without blocking execution.
 */
async function submitDndAuditArtifact(
    endpointUrl: string,
    workspaceName: string,
    enforcerId: string,
    actionType: string,
    commandText: string,
    buttonText: string,
    authToken?: string,
    context?: vscode.ExtensionContext
): Promise<void> {
    try {
        if (!context) {
            return;
        }

        const encryptionKey = await getEncryptionKey(context);
        if (!encryptionKey) {
            return;
        }

        const plaintextContent = JSON.stringify({
            actionType,
            commandText,
            buttonText: `DND audit: ${buttonText}`,
            workspace: workspaceName,
            repoName: "",
            source: "antigravity-enforcer-dnd",
        });

        const ciphertext: EncryptedPayload = encryptPayload(plaintextContent, encryptionKey);

        const metadata: Record<string, string> = {
            repoName: "",
            workspaceName,
            dndAudit: "true",
        };

        const artifactBody = {
            artifactType: "command-approval",
            artifactHash: crypto.createHash("sha256")
                .update(`dnd-audit:${actionType}:${commandText}:${Date.now()}`)
                .digest("hex"),
            ciphertext,
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
            metadata,
        };

        const envelope = {
            msgId: "msg-" + crypto.randomUUID(),
            msgType: "artifact.submit",
            requestId: "audit-" + crypto.randomUUID(),
            createdAt: new Date().toISOString(),
            sender: { enforcerId },
            body: artifactBody,
        };

        const submitUrl = `${endpointUrl}/v1/artifacts`;
        await httpRequest("POST", submitUrl, envelope, undefined, authToken);
    } catch {
        // Audit failures are non-fatal and must not affect command outcome.
    }
}

/**
 * Withdraw a pending approval request from the Gateway.
 * Called when the user takes manual action (clicks the button themselves)
 * and the pending exchange is no longer needed.
 * Fire-and-forget — errors are logged but don't affect the caller.
 */
export async function withdrawExchange(
    endpointUrl: string,
    requestId: string,
    out: vscode.OutputChannel,
    authToken?: string
): Promise<void> {
    try {
        const url = `${endpointUrl.replace(/\/$/, "")}/v1/exchanges/${requestId}/withdraw`;
        out.appendLine(`[Airlock] 🔄 Withdrawing exchange: ${requestId}`);
        await httpRequest("POST", url, undefined, undefined, authToken);
        out.appendLine(`[Airlock] ✓ Exchange withdrawn: ${requestId}`);
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        out.appendLine(`[Airlock] ⚠ Withdraw FAILED (non-fatal): ${msg}`);
    }
}
