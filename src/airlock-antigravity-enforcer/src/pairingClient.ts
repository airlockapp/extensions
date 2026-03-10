import * as http from "http";
import * as https from "https";
import * as vscode from "vscode";
import * as crypto from "crypto";



export interface PairingSession {
    pairingNonce: string;
    pairingCode: string;
    deviceId: string;
    gatewayUrl: string;
    localGatewayUrl: string;
    expiresAt: string;
}

export interface PairingStatus {
    pairingNonce: string;
    state: "Pending" | "Completed" | "Expired";
    responseJson: string | null;
    routingToken: string | null;
    expiresAt: string;
}

export interface PairingResponse {
    signerKeyId: string;
    publicKey: string;
    pairingNonce: string;
    timestamp: string;
    signature: string;
    x25519PublicKey?: string;
}

/**
 * Initiate a pairing session via the Gateway.
 * The Gateway generates pairingNonce + pairingCode and returns both.
 */
export async function initiatePairing(
    gatewayUrl: string,
    deviceId: string,
    enforcerId: string,
    out: vscode.OutputChannel,
    x25519PublicKey?: string,
    enforcerLabel?: string,
    token?: string,
    workspaceName?: string
): Promise<PairingSession> {
    const url = `${gatewayUrl}/v1/pairing/initiate`;
    out.appendLine(`[Airlock Pairing] Initiating: POST ${url}`);

    const body = JSON.stringify({ deviceId, gatewayUrl, enforcerId, x25519PublicKey, enforcerLabel, workspaceName });
    const result = await httpPost<PairingSession>(url, body, token);
    result.localGatewayUrl = gatewayUrl;

    out.appendLine(`[Airlock Pairing] Session created: code=${result.pairingCode}, expires=${result.expiresAt}`);
    return result;
}

/**
 * Poll the Gateway for pairing session status.
 */
export async function pollPairingStatus(
    gatewayUrl: string,
    nonce: string,
    token?: string
): Promise<PairingStatus> {
    const url = `${gatewayUrl}/v1/pairing/${encodeURIComponent(nonce)}/status`;
    return httpGet<PairingStatus>(url, token);
}

export function verifyPairingResponse(response: PairingResponse, out?: { appendLine(s: string): void }): boolean {
    const log = (msg: string) => out?.appendLine(`[Airlock Pairing] ${msg}`);

    const publicKeyBytes = Buffer.from(response.publicKey, "base64");
    log?.(`Verify: pubkey length=${publicKeyBytes.length} bytes (expect 32 for raw Ed25519)`);

    // Decode base64url signature — normalize to standard base64 with padding
    let sigB64 = response.signature.replace(/-/g, "+").replace(/_/g, "/");
    while (sigB64.length % 4 !== 0) { sigB64 += "="; }
    const signatureBytes = Buffer.from(sigB64, "base64");
    log?.(`Verify: signature length=${signatureBytes.length} bytes (expect 64 for Ed25519)`);

    // Build canonical payloads — try 5-field (Phase 3) first, then 4-field (legacy)
    const base = `${response.signerKeyId}|${response.publicKey}|${response.pairingNonce}|${response.timestamp}`;
    const candidates: string[] = [];
    if (response.x25519PublicKey) {
        candidates.push(`${base}|${response.x25519PublicKey}`);
    }
    candidates.push(base);

    for (const canonical of candidates) {
        const message = Buffer.from(canonical, "utf-8");
        log?.(`Verify: trying canonical: ${canonical}`);
        log?.(`Verify: signature base64: ${signatureBytes.toString("base64")}`);
        log?.(`Verify: pubkey base64: ${publicKeyBytes.toString("base64")}`);
        try {
            if (crypto.verify(null, message, {
                key: publicKeyBytes,
                format: "der",
                type: "spki"
            }, signatureBytes)) {
                log?.("Verify: ✓ passed (direct DER/SPKI)");
                return true;
            }
            log?.("Verify: direct DER/SPKI returned false");
        } catch (e: unknown) {
            log?.(`Verify: direct DER/SPKI threw: ${e instanceof Error ? e.message : String(e)}`);
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
                log?.("Verify: ✓ passed (raw + DER prefix)");
                return true;
            }
            log?.("Verify: raw + DER prefix returned false");
        } catch (e: unknown) {
            log?.(`Verify: raw + DER prefix threw: ${e instanceof Error ? e.message : String(e)}`);
        }
    }
    log?.("Verify: ✗ all verification attempts failed");
    return false;
}

/**
 * Compute a SHA-256 fingerprint of a public key for user confirmation.
 */
export function computeFingerprint(publicKeyBase64: string): string {
    const pubBytes = Buffer.from(publicKeyBase64, "base64");
    const hash = crypto.createHash("sha256").update(pubBytes).digest("hex");
    // Format as XX:XX:XX:XX... (first 16 hex chars = 8 bytes)
    return hash.slice(0, 16).match(/.{2}/g)!.join(":").toUpperCase();
}

/**
 * Store a paired signer key in VS Code workspace state.
 * Per HARP-KEYMGMT §5.1: HE MUST record signerKeyId, publicKey, deviceId, creation timestamp.
 * Scoped per workspace so each workspace has independent pairing.
 */
export async function storePairedKey(
    context: vscode.ExtensionContext,
    signerKeyId: string,
    publicKey: string,
    deviceId: string
): Promise<void> {
    const key = `airlock.pairedKeys`;
    const existing = context.workspaceState.get<Record<string, { publicKey: string; deviceId: string; pairedAt: string }>>(key) ?? {};
    existing[signerKeyId] = { publicKey, deviceId, pairedAt: new Date().toISOString() };
    await context.workspaceState.update(key, existing);
}

/**
 * Get all paired keys from VS Code global state.
 */
export function getPairedKeys(
    context: vscode.ExtensionContext
): Record<string, { publicKey: string; deviceId: string; pairedAt: string }> {
    return context.workspaceState.get<Record<string, { publicKey: string; deviceId: string; pairedAt: string }>>("airlock.pairedKeys") ?? {};
}

// ── HTTP helpers ────────────────────────────────────────────────────

function httpPost<T>(url: string, body: string, token?: string): Promise<T> {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const transport = parsed.protocol === "https:" ? https : http;

        const headers: Record<string, string | number> = {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
        };
        if (token) { headers["Authorization"] = `Bearer ${token}`; }

        const req = transport.request({
            hostname: parsed.hostname,
            port: parsed.port,
            path: parsed.pathname,
            method: "POST",
            headers,
            timeout: 10000,
        }, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(JSON.parse(data)); }
                    catch { reject(new Error("Invalid JSON response")); }
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
                }
            });
        });

        req.on("timeout", () => { req.destroy(); reject(new Error("Timeout (10s)")); });
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

function httpGet<T>(url: string, token?: string): Promise<T> {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const transport = parsed.protocol === "https:" ? https : http;

        const headers: Record<string, string> = {};
        if (token) { headers["Authorization"] = `Bearer ${token}`; }

        const req = transport.get({
            hostname: parsed.hostname,
            port: parsed.port,
            path: parsed.pathname + parsed.search,
            headers,
            timeout: 5000,
        }, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    try { resolve(JSON.parse(data)); }
                    catch { reject(new Error("Invalid JSON response")); }
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
                }
            });
        });

        req.on("timeout", () => { req.destroy(); reject(new Error("Timeout (5s)")); });
        req.on("error", reject);
    });
}
