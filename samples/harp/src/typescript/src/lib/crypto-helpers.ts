/**
 * Crypto helpers: base64url, SHA-256, HKDF, X25519, XChaCha20-Poly1305, Ed25519.
 * Mirrors Harp.Common/Crypto.cs + Harp.Common/NsecAead.cs.
 *
 * NOTE: libsodium-wrappers-sumo has a broken ESM distribution on Node 22.
 * We use createRequire() to load it via CJS as a workaround.
 */

import { createHash, hkdfSync, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

// Load libsodium via CJS to work around broken ESM distribution
const require = createRequire(import.meta.url ?? fileURLToPath(import.meta.url));
const sodium = require("libsodium-wrappers-sumo") as typeof import("libsodium-wrappers-sumo");

/** Must be called once before using any sodium-based functions. */
export async function initCrypto(): Promise<void> {
    await sodium.ready;
}

// ──────────────── Base64url ────────────────

export function toB64Url(buf: Uint8Array): string {
    return Buffer.from(buf).toString("base64url");
}

export function fromB64Url(s: string): Buffer {
    return Buffer.from(s, "base64url");
}

// ──────────────── Hashing ────────────────

export function sha256Hex(s: string): string {
    return createHash("sha256").update(s, "utf8").digest("hex");
}

// ──────────────── HKDF-SHA256 ────────────────

export function deriveKey(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number = 32,
): Buffer {
    return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

// ──────────────── X25519 Key Exchange ────────────────

export interface X25519Keypair {
    readonly publicKey: Buffer;
    readonly privateKey: Buffer;
}

export function createX25519Keypair(): X25519Keypair {
    const kp = sodium.crypto_box_keypair();
    return {
        publicKey: Buffer.from(kp.publicKey),
        privateKey: Buffer.from(kp.privateKey),
    };
}

export function x25519DeriveShared(
    myPrivateKey: Uint8Array,
    peerPublicKey: Uint8Array,
): Buffer {
    return Buffer.from(sodium.crypto_scalarmult(myPrivateKey, peerPublicKey));
}

// ──────────────── XChaCha20-Poly1305 AEAD ────────────────

export interface AeadResult {
    readonly nonce: Buffer;
    readonly ciphertext: Buffer;
    readonly tag: Buffer;
}

export function xchachaEncrypt(
    key32: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
): AeadResult {
    const nonceBytes = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const tagBytes = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;

    const nonce = Buffer.from(sodium.randombytes_buf(nonceBytes));
    const combined = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, null, nonce, key32,
    );

    const ciphertext = Buffer.from(combined.subarray(0, combined.length - tagBytes));
    const tag = Buffer.from(combined.subarray(combined.length - tagBytes));

    return { nonce, ciphertext, tag };
}

export function xchachaDecrypt(
    key32: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    tag: Uint8Array,
    aad: Uint8Array,
): Buffer {
    const combined = Buffer.concat([ciphertext, tag]);
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, combined, aad, nonce, key32,
    );

    if (!plaintext) {
        throw new Error("AEAD authentication failed.");
    }

    return Buffer.from(plaintext);
}

// ──────────────── Ed25519 Signing ────────────────

export interface Ed25519Keypair {
    readonly publicKey: Buffer;
    readonly privateKey: Buffer;
}

export function createEd25519Keypair(): Ed25519Keypair {
    const kp = sodium.crypto_sign_keypair();
    return {
        publicKey: Buffer.from(kp.publicKey),
        privateKey: Buffer.from(kp.privateKey),
    };
}

export function ed25519Sign(privateKey: Uint8Array, message: Uint8Array): Buffer {
    return Buffer.from(sodium.crypto_sign_detached(message, privateKey));
}

export function ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
): boolean {
    return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

// ──────────────── Random Bytes ────────────────

export { randomBytes };
