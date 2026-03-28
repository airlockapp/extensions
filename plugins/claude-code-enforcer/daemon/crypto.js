"use strict";

const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

function generateX25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  return {
    publicKey: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64url"),
    privateKey: privateKey
      .export({ type: "pkcs8", format: "der" })
      .toString("base64url"),
  };
}

function deriveSharedKey(localPrivateKeyBase64Url, remotePublicKeyBase64Url) {
  const privKey = crypto.createPrivateKey({
    key: Buffer.from(localPrivateKeyBase64Url, "base64url"),
    format: "der",
    type: "pkcs8",
  });

  let remotePubBuf = Buffer.from(remotePublicKeyBase64Url, "base64url");
  if (remotePubBuf.length === 32) {
    const X25519_SPKI_HEADER = Buffer.from("302a300506032b656e032100", "hex");
    remotePubBuf = Buffer.concat([X25519_SPKI_HEADER, remotePubBuf]);
  }
  const pubKey = crypto.createPublicKey({
    key: remotePubBuf,
    format: "der",
    type: "spki",
  });

  const sharedSecret = crypto.diffieHellman({
    publicKey: pubKey,
    privateKey: privKey,
  });

  const derivedKey = crypto.hkdfSync(
    "sha256",
    sharedSecret,
    Buffer.alloc(0),
    Buffer.from("HARP-E2E-AES256GCM", "utf-8"),
    KEY_BYTES
  );

  return Buffer.from(derivedKey).toString("base64url");
}

function encryptPayload(plaintext, keyBase64) {
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

module.exports = {
  generateX25519KeyPair,
  deriveSharedKey,
  encryptPayload,
};
