/**
 * HE Proposer — builds & encrypts artifacts.
 * Mirrors Harp.Executor/Program.cs.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { randomUUID } from "node:crypto";
import type { ArtifactWire, EncBlob, MaKeys } from "./lib/models.js";
import {
    initCrypto,
    toB64Url, fromB64Url, sha256Hex, deriveKey,
    createX25519Keypair, x25519DeriveShared,
    xchachaEncrypt, randomBytes,
} from "./lib/crypto-helpers.js";
import { jcsCanonicalize } from "./lib/canonical-json.js";

const MA_KEYS_FILE = "C:\\tmp\\harp\\ma-keys.json";
const ARTIFACT_WIRE_FILE = "C:\\tmp\\harp\\artifact-wire.json";

function preview(s: string): string {
    return s.length <= 18 ? s : s.substring(0, 18) + "...";
}

// ──────────────── Main ────────────────

async function main(): Promise<void> {
    await initCrypto();

    if (!existsSync(MA_KEYS_FILE)) {
        console.log(`Missing ${MA_KEYS_FILE}. Run harp-approver.ts once to generate MA keys.`);
        process.exit(1);
    }

    const maKeys: MaKeys = JSON.parse(readFileSync(MA_KEYS_FILE, "utf8"));

    console.log("Loaded MA public keys:");
    console.log(`  MA X25519 pub: ${preview(maKeys.maKxPubRawB64Url)}`);
    console.log(`  MA Ed25519 pub: ${preview(maKeys.maEd25519PubRawB64Url)}`);
    console.log(`  signerKeyId: ${maKeys.signerKeyId}`);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

    const payload = {
        command: 'echo "hello harp"',
        workingDirectory: "/tmp",
        timeoutSeconds: 10,
    } as const;

    const requestId = randomUUID().replace(/-/g, "");
    const artifactWithoutHash = {
        requestId,
        artifactType: "command.review",
        repoRef: "repo:opaque:demo",
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        payload,
        artifactHashAlg: "SHA-256",
    };

    const artifactHashHex = sha256Hex(jcsCanonicalize(artifactWithoutHash));

    const aadObj = {
        requestId,
        artifactType: "command.review",
        repoRef: "repo:opaque:demo",
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        artifactHashAlg: "SHA-256",
        artifactHash: artifactHashHex,
    };
    const aad = Buffer.from(jcsCanonicalize(aadObj), "utf8");

    // Key agreement
    const maKxPubRaw = fromB64Url(maKeys.maKxPubRawB64Url);
    const heKx = createX25519Keypair();
    const sharedSecret = x25519DeriveShared(heKx.privateKey, maKxPubRaw);

    const salt = randomBytes(16);
    const infoStr = "HARP-XCHACHA-PAYLOAD-V1";
    const info = Buffer.from(infoStr, "utf8");
    const keyMaterial = deriveKey(sharedSecret, salt, info, 32);

    // AEAD
    const payloadJson = JSON.stringify(payload);
    const payloadBytes = Buffer.from(payloadJson, "utf8");
    const { nonce, ciphertext, tag } = xchachaEncrypt(keyMaterial, payloadBytes, aad);

    const enc: EncBlob = {
        kdf: "X25519+HKDF-SHA256",
        encAlg: "XChaCha20-Poly1305",
        maKxPub: maKeys.maKxPubRawB64Url,
        heKxPub: toB64Url(heKx.publicKey),
        salt: toB64Url(salt),
        info: infoStr,
        nonce: toB64Url(nonce),
        ciphertext: toB64Url(ciphertext),
        tag: toB64Url(tag),
    };

    const artifactWire: ArtifactWire = {
        requestId,
        artifactType: "command.review",
        repoRef: "repo:opaque:demo",
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        artifactHashAlg: "SHA-256",
        artifactHash: artifactHashHex,
        enc,
    };

    mkdirSync("C:\\tmp\\harp", { recursive: true });
    writeFileSync(ARTIFACT_WIRE_FILE, JSON.stringify(artifactWire, null, 2));

    console.log();
    console.log("✅ Wrote artifact-wire.json");
    console.log(`artifactHash: ${artifactHashHex}`);
}

main();
