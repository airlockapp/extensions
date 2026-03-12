import * as vscode from "vscode";
import * as http from "http";
import * as https from "https";
import * as crypto from "crypto";
import { encryptPayload, getEncryptionKey, getRoutingToken, clearRoutingToken, type EncryptedPayload } from "./crypto.js";
import { getPairedKeys } from "./pairingClient.js";

export interface ApprovalResult {
    decision: "approve" | "reject";
    reason?: string;
    requestId: string;
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
    abortSignal?: AbortSignal
): Promise<ApprovalResult> {
    const ws = vscode.workspace.workspaceFolders?.[0];
    const requestId = externalRequestId ?? "req-" + crypto.randomUUID();
    const msgId = "msg-" + crypto.randomUUID();

    // Build HARP artifact.submit envelope
    const workspaceName = ws?.name || "unknown";

    // Sensitive display data — goes INSIDE encrypted ciphertext, NOT in cleartext metadata
    const plaintextContent = JSON.stringify({
        actionType,
        commandText,
        buttonText,
        workspace: workspaceName,
        repoName: "",
        source: "copilot-enforcer",
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
    out.appendLine("[Airlock] Artifact encrypted with AES-256-GCM");

    const routingToken = context ? getRoutingToken(context) : null;
    const metadata: Record<string, string> = {};

    if (routingToken) {
        // Privacy-preserving: Gateway routes by opaque token, cannot see real approverId
        metadata.routingToken = routingToken;
        out.appendLine(`[Airlock] Using opaque routing token (${routingToken.length} chars)`);
    } else {
        // Backward compatible: send real approverId if no routing token available
        const approverId = vscode.workspace.getConfiguration("airlock").get<string>("approverId");
        if (approverId) { metadata.approverId = approverId; }
    }


    // Workspace identity — cleartext so the mobile app can group items by workspace
    metadata.repoName = "";
    metadata.workspaceName = workspaceName;

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
            enforcerId: context?.workspaceState.get<string>("airlock.enforcerId")
                || vscode.workspace.getConfiguration("airlock").get<string>("enforcerId")
                || "enforcer-vscode"
        },
        body: artifactBody,
    };

    // Step 1: Submit artifact
    const submitUrl = `${endpointUrl}/v1/artifacts`;
    out.appendLine(`[Airlock] Submitting artifact: ${actionType} → ${submitUrl}`);

    try {
        const submitResult = await httpRequest("POST", submitUrl, envelope);
        out.appendLine(`[Airlock] Artifact accepted: requestId=${requestId}`);
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        out.appendLine(`[Airlock] ✗ Artifact submit failed: ${msg}`);

        // Detect stale routing token / no approver
        if (msg.includes("no_approver") || msg.includes("422")) {
            out.appendLine(`[Airlock] ⚠ Routing token may be stale. Clearing and prompting re-pair.`);
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

    // Step 2: Long-poll for decision (use 25s server-side intervals for retries)
    const pollIntervalSec = 25;
    const deadline = Date.now() + timeoutSeconds * 1000;
    let pollCount = 0;

    while (Date.now() < deadline) {
        pollCount++;
        const remainingSec = Math.ceil((deadline - Date.now()) / 1000);
        const serverTimeout = Math.min(pollIntervalSec, remainingSec);
        if (serverTimeout <= 0) break;

        const waitUrl = `${endpointUrl}/v1/exchanges/${requestId}/wait?timeout=${serverTimeout}`;
        out.appendLine(`[Airlock] Poll ${pollCount}: waiting ${serverTimeout}s for decision...`);

        // Check if aborted between polls
        if (abortSignal?.aborted) {
            throw new Error("Approval aborted — manual action detected");
        }

        try {
            const waitResult = await httpRequest("GET", waitUrl, undefined, abortSignal);

            if (!waitResult) {
                // 204 No Content — no decision yet, poll again
                out.appendLine(`[Airlock] Poll ${pollCount}: no decision yet, will retry.`);
                continue;
            }

            // Parse decision.deliver response
            const decision = parseDecision(waitResult, context, out);
            if (decision) {
                out.appendLine(
                    `[Airlock] Decision: ${decision.decision}${decision.reason ? ` (${decision.reason})` : ""}`
                );
                return { ...decision, requestId };
            }

            // Unknown response — keep polling
            out.appendLine(`[Airlock] Poll ${pollCount}: unexpected response, retrying...`);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            // Transient errors — keep polling until deadline
            if (Date.now() < deadline) {
                out.appendLine(`[Airlock] Poll ${pollCount} error (retrying): ${msg}`);
                await sleep(1000);
            } else {
                throw err;
            }
        }
    }

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
        // Signature fields missing — fail closed per HARP-CORE §6.3
        out?.appendLine(`[Airlock] ⚠ Decision missing signature fields (signerKeyId=${signerKeyId ? 'present' : 'missing'}, signature=${signature ? 'present' : 'missing'}, nonce=${nonce ? 'present' : 'missing'}, artifactHash=${artifactHash ? 'present' : 'missing'})`);
        out?.appendLine(`[Airlock] ✗ Rejecting unsigned decision per HARP-CORE §6.3`);
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

        const reqHeaders: Record<string, string | number> = data
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data),
            }
            : {};
        if (authToken) { reqHeaders["Authorization"] = `Bearer ${authToken}`; }

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
        await httpRequest("POST", url, undefined, undefined, authToken);
        out.appendLine(`[Airlock] ✓ Withdrawn exchange: ${requestId}`);
    } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        out.appendLine(`[Airlock] ⚠ Withdraw failed (non-fatal): ${msg}`);
    }
}
