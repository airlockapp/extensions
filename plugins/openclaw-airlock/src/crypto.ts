/**
 * Cryptographic utilities for Airlock plugin.
 *
 * - X25519 key pair generation and ECDH shared key derivation
 * - Ed25519 decision signature verification
 *
 * These mirror the Claude Code enforcer's crypto.js and pairing.js patterns.
 */

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  verify,
} from "node:crypto";

// ── Constants ───────────────────────────────────────────────────

const AES_KEY_BYTES = 32;
const HKDF_INFO = "HARP-E2E-AES256GCM";

/** ASN.1 DER prefix for X25519 SPKI encoding (raw 32-byte key → DER). */
const X25519_SPKI_HEADER = Buffer.from("302a300506032b656e032100", "hex");

/** ASN.1 DER prefix for Ed25519 SPKI encoding (raw 32-byte key → DER). */
const ED25519_SPKI_HEADER = Buffer.from("302a300506032b6570032100", "hex");

// ── X25519 Key Exchange ─────────────────────────────────────────

export interface X25519KeyPair {
  /** Base64url-encoded SPKI DER public key. */
  publicKey: string;
  /** Base64url-encoded PKCS8 DER private key. */
  privateKey: string;
}

/** Generate an X25519 key pair for ECDH key exchange. */
export function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKey: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64url"),
    privateKey: privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64url"),
  };
}

/**
 * Derive a shared AES-256-GCM key from local X25519 private key and remote X25519 public key.
 *
 * Uses ECDH + HKDF-SHA256 with info "HARP-E2E-AES256GCM" (matching all other Airlock SDKs).
 *
 * @param localPrivateKeyBase64Url PKCS8 DER private key (base64url).
 * @param remotePublicKeyBase64Url SPKI DER or raw 32-byte public key (base64url).
 * @returns AES-256-GCM key as base64url string.
 */
export function deriveSharedKey(
  localPrivateKeyBase64Url: string,
  remotePublicKeyBase64Url: string,
): string {
  const privKey = createPrivateKey({
    key: Buffer.from(localPrivateKeyBase64Url, "base64url"),
    format: "der",
    type: "pkcs8",
  });

  // Handle both raw 32-byte and full SPKI DER formats
  let remotePubBuf = Buffer.from(remotePublicKeyBase64Url, "base64url");
  if (remotePubBuf.length === 32) {
    remotePubBuf = Buffer.concat([X25519_SPKI_HEADER, remotePubBuf]);
  }

  const pubKey = createPublicKey({
    key: remotePubBuf,
    format: "der",
    type: "spki",
  });

  const sharedSecret = diffieHellman({
    publicKey: pubKey,
    privateKey: privKey,
  });

  const derivedKey = hkdfSync(
    "sha256",
    sharedSecret,
    Buffer.alloc(0),           // no salt
    Buffer.from(HKDF_INFO, "utf-8"), // info
    AES_KEY_BYTES,
  );

  return Buffer.from(derivedKey).toString("base64url");
}

// ── Decision Signature Verification ─────────────────────────────

export interface PairedKeyEntry {
  /** Base64 public key (DER or raw Ed25519). */
  publicKey: string;
  /** Device identifier. */
  deviceId: string;
}

/**
 * Verify an Ed25519 decision signature.
 *
 * Canonical format: `${artifactHash}|${decision}|${nonce}`
 *
 * @returns True if the signature is valid, false otherwise.
 */
export function verifyDecisionSignature(
  pairedKeys: Record<string, PairedKeyEntry>,
  artifactHash: string,
  decision: string,
  nonce: string,
  signatureBase64Url: string,
  signerKeyId: string,
): boolean {
  // Look up the signer's public key (try multiple key ID variants)
  const keyEntry =
    pairedKeys[signerKeyId] ??
    pairedKeys[signerKeyId.replace(/^key-/, "")] ??
    pairedKeys[`key-${signerKeyId}`];

  if (!keyEntry) {
    return false;
  }

  // Decode the signature from base64url → standard base64
  let sigB64 = signatureBase64Url.replace(/-/g, "+").replace(/_/g, "/");
  while (sigB64.length % 4 !== 0) sigB64 += "=";
  const signatureBytes = Buffer.from(sigB64, "base64");

  // Build canonical message
  const canonical = `${artifactHash}|${decision}|${nonce}`;
  const message = Buffer.from(canonical, "utf-8");
  const publicKeyBytes = Buffer.from(keyEntry.publicKey, "base64");

  // Try verification with full DER SPKI first
  try {
    if (
      verify(
        null,
        message,
        { key: publicKeyBytes, format: "der", type: "spki" },
        signatureBytes,
      )
    ) {
      return true;
    }
  } catch {
    // Might be raw key, try wrapping with Ed25519 header
  }

  // Try with raw 32-byte key wrapped in Ed25519 SPKI header
  try {
    const keyObj = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_HEADER, publicKeyBytes]),
      format: "der",
      type: "spki",
    });
    if (verify(null, message, keyObj, signatureBytes)) {
      return true;
    }
  } catch {
    // Verification failed
  }

  return false;
}
