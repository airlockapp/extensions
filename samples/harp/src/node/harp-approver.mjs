// harp-approver.mjs
// Mobile Approver — generates MA keys (first run), decrypts artifact, signs decision
// Mirrors Harp.Approver/Program.cs

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import {
    toB64Url, fromB64Url, sha256Hex, deriveKey,
    createX25519Keypair, x25519DeriveShared,
    createEd25519Keypair, ed25519Sign, ed25519Verify,
    xchachaDecrypt, randomBytes,
} from './lib/crypto-helpers.mjs';
import { jcsCanonicalize } from './lib/canonical-json.mjs';

const MA_KEYS_FILE = 'C:\\tmp\\harp\\ma-keys.json';
const ARTIFACT_WIRE_FILE = 'C:\\tmp\\harp\\artifact-wire.json';
const DECISION_FILE = 'C:\\tmp\\harp\\decision.json';

function preview(s) {
    return s.length <= 18 ? s : s.substring(0, 18) + '...';
}

function prompt(question) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

// ──────────────── Key Bootstrap ────────────────

function ensureKeysExist() {
    if (existsSync(MA_KEYS_FILE)) return;

    console.log('Generating MA keys...');

    // X25519 keypair for payload decryption
    const kxKp = createX25519Keypair();

    // Ed25519 keypair for decision signing
    const signKp = createEd25519Keypair();

    const keys = {
        maKxPubRawB64Url: toB64Url(kxKp.publicKey),
        maKxPrivRawB64Url: toB64Url(kxKp.privateKey),
        maEd25519PubRawB64Url: toB64Url(signKp.publicKey),
        maEd25519PrivRawB64Url: toB64Url(signKp.privateKey),
        signerKeyId: 'ma-key-1',
    };

    mkdirSync('C:\\tmp\\harp', { recursive: true });
    writeFileSync(MA_KEYS_FILE, JSON.stringify(keys, null, 2));
    console.log(`✅ Wrote ${MA_KEYS_FILE}`);
}

// ──────────────── Main ────────────────

ensureKeysExist();

const keys = JSON.parse(readFileSync(MA_KEYS_FILE, 'utf8'));
const maKxPrivRaw = fromB64Url(keys.maKxPrivRawB64Url);
const maKxPubB64Url = keys.maKxPubRawB64Url;
const maSignPrivRaw = fromB64Url(keys.maEd25519PrivRawB64Url);
const maSignPubRaw = fromB64Url(keys.maEd25519PubRawB64Url);
const signerKeyId = keys.signerKeyId;

if (!existsSync(ARTIFACT_WIRE_FILE)) {
    console.log(`Missing ${ARTIFACT_WIRE_FILE}. Run harp-executor.mjs first.`);
    process.exit(0); // First run was just key generation
}

const artifactWire = JSON.parse(readFileSync(ARTIFACT_WIRE_FILE, 'utf8'));

// Basic enc sanity
if (artifactWire.enc.encAlg !== 'XChaCha20-Poly1305') {
    console.log(`❌ Unsupported encAlg: ${artifactWire.enc.encAlg}`);
    process.exit(1);
}
if (artifactWire.enc.kdf !== 'X25519+HKDF-SHA256') {
    console.log(`❌ Unsupported kdf: ${artifactWire.enc.kdf}`);
    process.exit(1);
}

// Rebuild AAD (must match HE)
const aadObj = {
    requestId: artifactWire.requestId,
    artifactType: artifactWire.artifactType,
    repoRef: artifactWire.repoRef,
    createdAt: artifactWire.createdAt,
    expiresAt: artifactWire.expiresAt,
    artifactHashAlg: artifactWire.artifactHashAlg,
    artifactHash: artifactWire.artifactHash,
};
const aad = Buffer.from(jcsCanonicalize(aadObj), 'utf8');

// ──── Key agreement + HKDF ────

const heKxPubRaw = fromB64Url(artifactWire.enc.heKxPub);
const sharedSecret = x25519DeriveShared(maKxPrivRaw, heKxPubRaw);

const salt = fromB64Url(artifactWire.enc.salt);
const info = Buffer.from(artifactWire.enc.info || 'HARP-XCHACHA-PAYLOAD-V1', 'utf8');
const keyMaterial = deriveKey(sharedSecret, salt, info, 32);

// ──── AEAD decrypt ────

const nonce = fromB64Url(artifactWire.enc.nonce);
const ciphertext = fromB64Url(artifactWire.enc.ciphertext);
const tag = fromB64Url(artifactWire.enc.tag);

let plaintext;
try {
    plaintext = xchachaDecrypt(keyMaterial, nonce, ciphertext, tag, aad);
} catch (err) {
    console.log(`❌ Decryption/auth failed: ${err.message}`);
    process.exit(1);
}

const payloadJson = plaintext.toString('utf8');
const payloadObj = JSON.parse(payloadJson);

// ──── Verify artifactHash by reconstructing plaintext artifact without artifactHash ────

const artifactWithoutHash = {
    requestId: artifactWire.requestId,
    artifactType: artifactWire.artifactType,
    repoRef: artifactWire.repoRef,
    createdAt: artifactWire.createdAt,
    expiresAt: artifactWire.expiresAt,
    payload: payloadObj,
    artifactHashAlg: artifactWire.artifactHashAlg,
};

const recomputed = sha256Hex(jcsCanonicalize(artifactWithoutHash));
if (recomputed.toLowerCase() !== artifactWire.artifactHash.toLowerCase()) {
    console.log('❌ Hash mismatch. Refuse.');
    console.log(`Expected: ${artifactWire.artifactHash}`);
    console.log(`Actual:   ${recomputed}`);
    process.exit(1);
}

console.log('✅ Payload decrypted and artifactHash verified.');
console.log();
console.log('----- REVIEW PAYLOAD -----');
console.log(payloadJson);
console.log('--------------------------');
console.log();

const answer = (await prompt('Approve? (y/n): ')).trim().toLowerCase();
const decisionValue = answer === 'y' ? 'allow' : 'deny';

const decisionExpires = new Date(Date.now() + 10 * 60 * 1000);
const decisionNonce = toB64Url(randomBytes(16));

// Build DecisionSignable and sign
const signable = {
    requestId: artifactWire.requestId,
    artifactHashAlg: artifactWire.artifactHashAlg,
    artifactHash: artifactWire.artifactHash,
    repoRef: artifactWire.repoRef,
    decision: decisionValue,
    scope: 'once',
    expiresAt: decisionExpires.toISOString(),
    nonce: decisionNonce,
    sigAlg: 'Ed25519',
    signerKeyId,
};

const signableCanon = Buffer.from(jcsCanonicalize(signable), 'utf8');
const signature = ed25519Sign(maSignPrivRaw, signableCanon);

// Optional self-verify
if (!ed25519Verify(maSignPubRaw, signableCanon, signature)) {
    console.log('❌ Signature self-verify failed.');
    process.exit(1);
}

const decision = {
    ...signable,
    signature: toB64Url(signature),
};

writeFileSync(DECISION_FILE, JSON.stringify(decision, null, 2));
console.log(`✅ Wrote ${DECISION_FILE} (${decision.decision})`);
