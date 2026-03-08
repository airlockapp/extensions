// lib/crypto-helpers.mjs
// Base64url, SHA-256, HKDF-SHA256, X25519, XChaCha20-Poly1305, Ed25519
// Mirrors Harp.Common/Crypto.cs + Harp.Common/NsecAead.cs

import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import sodium from 'libsodium-wrappers-sumo';

// Ensure sodium is ready before any crypto operations
await sodium.ready;

// ──────────────── Base64url ────────────────

export function toB64Url(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function fromB64Url(s) {
  return Buffer.from(s, 'base64url');
}

// ──────────────── Hashing ────────────────

export function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

// ──────────────── HKDF-SHA256 ────────────────

export function deriveKey(ikm, salt, info, length = 32) {
  return Buffer.from(hkdfSync('sha256', ikm, salt, info, length));
}

// ──────────────── X25519 Key Exchange ────────────────

export function createX25519Keypair() {
  // crypto_box_keypair generates X25519 keypair
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: Buffer.from(kp.publicKey),
    privateKey: Buffer.from(kp.privateKey),
  };
}

export function x25519DeriveShared(myPrivateKey, peerPublicKey) {
  return Buffer.from(sodium.crypto_scalarmult(myPrivateKey, peerPublicKey));
}

// ──────────────── XChaCha20-Poly1305 AEAD ────────────────

const XCHACHA_NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24
const XCHACHA_TAG_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;       // 16

export function xchachaEncrypt(key32, plaintext, aad) {
  const nonce = Buffer.from(sodium.randombytes_buf(XCHACHA_NONCE_BYTES));
  const combined = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext, aad, null, nonce, key32,
  );

  // combined = ciphertext || tag (last 16 bytes)
  const ciphertext = Buffer.from(combined.subarray(0, combined.length - XCHACHA_TAG_BYTES));
  const tag = Buffer.from(combined.subarray(combined.length - XCHACHA_TAG_BYTES));

  return { nonce, ciphertext, tag };
}

export function xchachaDecrypt(key32, nonce, ciphertext, tag, aad) {
  // Recombine ciphertext || tag for libsodium
  const combined = Buffer.concat([ciphertext, tag]);

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, combined, aad, nonce, key32,
  );

  if (!plaintext) {
    throw new Error('AEAD authentication failed.');
  }

  return Buffer.from(plaintext);
}

// ──────────────── Ed25519 Signing ────────────────

export function createEd25519Keypair() {
  const kp = sodium.crypto_sign_keypair();
  return {
    publicKey: Buffer.from(kp.publicKey),   // 32 bytes
    privateKey: Buffer.from(kp.privateKey), // 64 bytes (seed + pub)
  };
}

export function ed25519Sign(privateKey, message) {
  return Buffer.from(sodium.crypto_sign_detached(message, privateKey));
}

export function ed25519Verify(publicKey, message, signature) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

// ──────────────── Random Bytes ────────────────

export { randomBytes };
