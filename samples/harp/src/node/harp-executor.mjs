// harp-executor.mjs
// HE Proposer — builds & encrypts artifacts
// Mirrors Harp.Executor/Program.cs

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import {
    toB64Url, fromB64Url, sha256Hex, deriveKey,
    createX25519Keypair, x25519DeriveShared,
    xchachaEncrypt, randomBytes,
} from './lib/crypto-helpers.mjs';
import { jcsCanonicalize } from './lib/canonical-json.mjs';

const MA_KEYS_FILE = 'C:\\tmp\\harp\\ma-keys.json';
const ARTIFACT_WIRE_FILE = 'C:\\tmp\\harp\\artifact-wire.json';

function preview(s) {
    return s.length <= 18 ? s : s.substring(0, 18) + '...';
}

// ──────────────── Main ────────────────

if (!existsSync(MA_KEYS_FILE)) {
    console.log(`Missing ${MA_KEYS_FILE}. Run harp-approver.mjs once to generate MA keys.`);
    process.exit(1);
}

const maKeys = JSON.parse(readFileSync(MA_KEYS_FILE, 'utf8'));
const maKxPubB64Url = maKeys.maKxPubRawB64Url;
const maSignPubB64Url = maKeys.maEd25519PubRawB64Url;
const signerKeyId = maKeys.signerKeyId;

console.log('Loaded MA public keys:');
console.log(`  MA X25519 pub: ${preview(maKxPubB64Url)}`);
console.log(`  MA Ed25519 pub: ${preview(maSignPubB64Url)}`);
console.log(`  signerKeyId: ${signerKeyId}`);

const now = new Date();
const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

// Payload (reviewable content)
const payload = {
    command: 'echo "hello harp"',
    workingDirectory: '/tmp',
    timeoutSeconds: 10,
};

// Build "artifact-without artifactHash" for hashing
const requestId = randomUUID().replace(/-/g, '');
const artifactWithoutHash = {
    requestId,
    artifactType: 'command.review',
    repoRef: 'repo:opaque:demo',
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    payload,
    artifactHashAlg: 'SHA-256',
};

const artifactHashHex = sha256Hex(jcsCanonicalize(artifactWithoutHash));

// Build AAD (bind encryption to immutable header + hash)
const aadObj = {
    requestId,
    artifactType: 'command.review',
    repoRef: 'repo:opaque:demo',
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    artifactHashAlg: 'SHA-256',
    artifactHash: artifactHashHex,
};
const aad = Buffer.from(jcsCanonicalize(aadObj), 'utf8');

// ──── Key agreement (X25519) + HKDF-SHA256 → 32-byte AEAD key ────

const maKxPubRaw = fromB64Url(maKxPubB64Url);

// Generate ephemeral HE X25519 keypair
const heKx = createX25519Keypair();

// Shared secret
const sharedSecret = x25519DeriveShared(heKx.privateKey, maKxPubRaw);

// HKDF inputs
const salt = randomBytes(16);
const infoStr = 'HARP-XCHACHA-PAYLOAD-V1';
const info = Buffer.from(infoStr, 'utf8');
const keyMaterial = deriveKey(sharedSecret, salt, info, 32);

// ──── AEAD XChaCha20-Poly1305 ────
const payloadJson = JSON.stringify(payload);
const payloadBytes = Buffer.from(payloadJson, 'utf8');
const { nonce, ciphertext, tag } = xchachaEncrypt(keyMaterial, payloadBytes, aad);

// Build ArtifactWire (payload is encrypted)
const artifactWire = {
    requestId,
    artifactType: 'command.review',
    repoRef: 'repo:opaque:demo',
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    artifactHashAlg: 'SHA-256',
    artifactHash: artifactHashHex,
    enc: {
        kdf: 'X25519+HKDF-SHA256',
        encAlg: 'XChaCha20-Poly1305',
        maKxPub: maKxPubB64Url,
        heKxPub: toB64Url(heKx.publicKey),
        salt: toB64Url(salt),
        info: infoStr,
        nonce: toB64Url(nonce),
        ciphertext: toB64Url(ciphertext),
        tag: toB64Url(tag),
    },
};

mkdirSync('C:\\tmp\\harp', { recursive: true });
writeFileSync(ARTIFACT_WIRE_FILE, JSON.stringify(artifactWire, null, 2));

console.log();
console.log('✅ Wrote artifact-wire.json');
console.log(`artifactHash: ${artifactHashHex}`);
