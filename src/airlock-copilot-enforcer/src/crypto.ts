import * as crypto from "crypto";
import * as vscode from "vscode";

const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export interface EncryptedPayload {
    alg: "AES-256-GCM";
    data: string;   // base64
    nonce: string;   // base64
    tag: string;     // base64
}

/**
 * Generate a 256-bit random encryption key for AES-256-GCM.
 * Returns base64url-encoded key.
 * @deprecated Use X25519 key exchange (generateX25519KeyPair + deriveSharedKey) for new pairings.
 */
export function generateEncryptionKey(): string {
    return crypto.randomBytes(KEY_BYTES)
        .toString("base64url");
}

// ── X25519 ECDH Key Agreement (HARP-KEYMGMT §2.3) ─────────────

export interface X25519KeyPair {
    publicKey: string;   // base64url
    privateKey: string;  // base64url (kept in memory/globalState only)
}

/**
 * Generate an ephemeral X25519 keypair for ECDH key agreement.
 * Per HARP-KEYMGMT §2.3: "Ephemeral ECDH (X25519)"
 */
export function generateX25519KeyPair(): X25519KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
    return {
        publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
        privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
    };
}

/**
 * Derive a shared AES-256-GCM key from ECDH key agreement.
 * Uses X25519 ECDH + HKDF-SHA256 to derive a 256-bit key.
 *
 * @param localPrivateKeyBase64Url Our X25519 private key (base64url, DER/PKCS8)
 * @param remotePublicKeyBase64Url Their X25519 public key (base64url, DER/SPKI)
 * @returns The derived 256-bit AES key as base64url.
 */
export function deriveSharedKey(
    localPrivateKeyBase64Url: string,
    remotePublicKeyBase64Url: string
): string {
    const privKey = crypto.createPrivateKey({
        key: Buffer.from(localPrivateKeyBase64Url, "base64url"),
        format: "der",
        type: "pkcs8",
    });

    // Remote public key may be:
    //   - 44 bytes: DER/SPKI format (from Node.js extension)
    //   - 32 bytes: raw key (from Dart/mobile cryptography package)
    let remotePubBuf = Buffer.from(remotePublicKeyBase64Url, "base64url");
    if (remotePubBuf.length === 32) {
        // Wrap raw 32-byte key in X25519 SPKI DER header
        const X25519_SPKI_HEADER = Buffer.from("302a300506032b656e032100", "hex");
        remotePubBuf = Buffer.concat([X25519_SPKI_HEADER, remotePubBuf]);
    }
    const pubKey = crypto.createPublicKey({
        key: remotePubBuf,
        format: "der",
        type: "spki",
    });

    // ECDH shared secret
    const sharedSecret = crypto.diffieHellman({
        publicKey: pubKey,
        privateKey: privKey,
    });

    // HKDF-SHA256 to derive 256-bit AES key
    const derivedKey = crypto.hkdfSync(
        "sha256",
        sharedSecret,
        Buffer.alloc(0), // no salt (both sides must agree)
        Buffer.from("HARP-E2E-AES256GCM", "utf-8"), // info string per HARP context
        KEY_BYTES
    );

    return Buffer.from(derivedKey).toString("base64url");
}

// ── X25519 key storage ──────────────────────────────────────────

const X25519_PRIVATE_KEY_STORE = "airlock.x25519PrivateKey";
const X25519_PUBLIC_KEY_STORE = "airlock.x25519PublicKey";

/**
 * Store X25519 keypair — private key in SecretStorage, public key in workspaceState.
 * Scoped per workspace so each workspace has its own pairing keys.
 */
export async function storeX25519KeyPair(
    context: vscode.ExtensionContext,
    keyPair: X25519KeyPair
): Promise<void> {
    await context.secrets.store(X25519_PRIVATE_KEY_STORE, keyPair.privateKey);
    await context.workspaceState.update(X25519_PUBLIC_KEY_STORE, keyPair.publicKey);
}

/**
 * Get stored X25519 private key for deriving shared secret.
 */
export async function getX25519PrivateKey(
    context: vscode.ExtensionContext
): Promise<string | null> {
    return (await context.secrets.get(X25519_PRIVATE_KEY_STORE)) ?? null;
}

/**
 * Encrypt a plaintext JSON payload with AES-256-GCM.
 * @param plaintext The plaintext JSON string to encrypt.
 * @param keyBase64 The 256-bit key as base64url.
 * @returns EncryptedPayload with base64-encoded fields.
 */
export function encryptPayload(plaintext: string, keyBase64: string): EncryptedPayload {
    const key = Buffer.from(keyBase64, "base64url");
    if (key.length !== KEY_BYTES) {
        throw new Error(`Invalid key length: expected ${KEY_BYTES}, got ${key.length}`);
    }

    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv(ALGORITHM, key, nonce);

    const encrypted = Buffer.concat([
        cipher.update(plaintext, "utf-8"),
        cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    return {
        alg: "AES-256-GCM",
        data: encrypted.toString("base64"),
        nonce: nonce.toString("base64"),
        tag: tag.toString("base64"),
    };
}

/**
 * Decrypt an AES-256-GCM encrypted payload.
 * @param payload The encrypted payload.
 * @param keyBase64 The 256-bit key as base64url.
 * @returns Decrypted plaintext string.
 */
export function decryptPayload(payload: EncryptedPayload, keyBase64: string): string {
    const key = Buffer.from(keyBase64, "base64url");
    const data = Buffer.from(payload.data, "base64");
    const nonce = Buffer.from(payload.nonce, "base64");
    const tag = Buffer.from(payload.tag, "base64");

    const decipher = crypto.createDecipheriv(ALGORITHM, key, nonce);
    decipher.setAuthTag(tag);

    return Buffer.concat([
        decipher.update(data),
        decipher.final(),
    ]).toString("utf-8");
}

// ── Key storage in VS Code SecretStorage ────────────────────────
// Encryption key is stored per-workspace (scoped by workspace folder name)
// so that different workspaces have independent pairing.

const ENCRYPTION_KEY_PREFIX = "airlock.encryptionKey";

/** Get workspace-scoped secret key name. */
function wsEncryptionKeyName(): string {
    const wsName = vscode.workspace.workspaceFolders?.[0]?.name ?? "default";
    return `${ENCRYPTION_KEY_PREFIX}.${wsName}`;
}

/**
 * Store the shared encryption key in VS Code SecretStorage (OS keychain).
 * Scoped per workspace folder.
 */
export async function storeEncryptionKey(
    context: vscode.ExtensionContext,
    keyBase64: string
): Promise<void> {
    await context.secrets.store(wsEncryptionKeyName(), keyBase64);
}

/**
 * Get the shared encryption key from VS Code SecretStorage.
 * Scoped per workspace folder.
 * Returns null if no key is stored.
 */
export async function getEncryptionKey(
    context: vscode.ExtensionContext
): Promise<string | null> {
    return (await context.secrets.get(wsEncryptionKeyName())) ?? null;
}

/**
 * Clear the encryption key (used when unpairing).
 */
export async function clearEncryptionKey(
    context: vscode.ExtensionContext
): Promise<void> {
    await context.secrets.delete(wsEncryptionKeyName());
}

// ── Routing token storage (per-workspace) ───────────────────────
// Uses workspaceState so each workspace has its own pairing.

const ROUTING_TOKEN_STORE = "airlock.routingToken";

/**
 * Store the opaque routing token from Gateway pairing.
 * Stored in workspaceState — each workspace has its own pairing.
 */
export async function storeRoutingToken(
    context: vscode.ExtensionContext,
    token: string
): Promise<void> {
    await context.workspaceState.update(ROUTING_TOKEN_STORE, token);
}

/**
 * Get the stored opaque routing token.
 * Returns null if no token is stored (not paired in this workspace).
 */
export function getRoutingToken(
    context: vscode.ExtensionContext
): string | null {
    return context.workspaceState.get<string>(ROUTING_TOKEN_STORE) ?? null;
}

/**
 * Clear the stored routing token (used when unpairing).
 */
export async function clearRoutingToken(
    context: vscode.ExtensionContext
): Promise<void> {
    await context.workspaceState.update(ROUTING_TOKEN_STORE, undefined);
}

