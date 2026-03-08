/**
 * HE Verifier — verifies Decision signature, binds to Artifact, enforces expiry & replay.
 * Mirrors Harp.Enforcer/Program.cs.
 */

import { readFileSync, existsSync } from "node:fs";
import type { ArtifactWire, Decision, DecisionSignable, MaKeys } from "./lib/models.js";
import { initCrypto, fromB64Url, ed25519Verify } from "./lib/crypto-helpers.js";
import { jcsCanonicalize } from "./lib/canonical-json.js";
import { NonceJournalStore } from "./lib/nonce-journal.js";

const MA_KEYS_FILE = "C:\\tmp\\harp\\ma-keys.json";
const ARTIFACT_WIRE_FILE = "C:\\tmp\\harp\\artifact-wire.json";
const DECISION_FILE = "C:\\tmp\\harp\\decision.json";
const NONCE_JOURNAL_FILE = "C:\\tmp\\harp\\nonce-journal.ndjson";

function fail(msg: string): never {
    console.log("❌ REJECT: " + msg);
    process.exit(1);
}

// ──────────────── Main ────────────────

async function main(): Promise<void> {
    await initCrypto();

    if (!existsSync(MA_KEYS_FILE)) fail(`Missing ${MA_KEYS_FILE}.`);
    if (!existsSync(ARTIFACT_WIRE_FILE)) fail(`Missing ${ARTIFACT_WIRE_FILE}.`);
    if (!existsSync(DECISION_FILE)) fail(`Missing ${DECISION_FILE}.`);

    const keys: MaKeys = JSON.parse(readFileSync(MA_KEYS_FILE, "utf8"));
    const artifactWire: ArtifactWire = JSON.parse(readFileSync(ARTIFACT_WIRE_FILE, "utf8"));
    const decision: Decision = JSON.parse(readFileSync(DECISION_FILE, "utf8"));

    // Binding checks
    if (decision.requestId !== artifactWire.requestId)
        fail("Decision.requestId != Artifact.requestId");
    if (decision.repoRef !== artifactWire.repoRef)
        fail("Decision.repoRef != Artifact.repoRef");
    if (decision.artifactHashAlg !== artifactWire.artifactHashAlg)
        fail("Decision.artifactHashAlg != Artifact.artifactHashAlg");
    if (decision.artifactHash.toLowerCase() !== artifactWire.artifactHash.toLowerCase())
        fail("Decision.artifactHash != Artifact.artifactHash");

    // Expiry checks
    const now = new Date();
    if (now > new Date(artifactWire.expiresAt))
        fail(`Artifact expired at ${artifactWire.expiresAt}`);
    if (now > new Date(decision.expiresAt))
        fail(`Decision expired at ${decision.expiresAt}`);

    // Signer checks
    if (decision.sigAlg !== "Ed25519")
        fail(`Unsupported sigAlg: ${decision.sigAlg}`);
    if (decision.signerKeyId !== keys.signerKeyId)
        fail(`Unknown signerKeyId: ${decision.signerKeyId}`);

    // Verify signature
    const signable: DecisionSignable = {
        requestId: decision.requestId,
        artifactHashAlg: decision.artifactHashAlg,
        artifactHash: decision.artifactHash,
        repoRef: decision.repoRef,
        decision: decision.decision,
        scope: decision.scope,
        expiresAt: decision.expiresAt,
        nonce: decision.nonce,
        sigAlg: decision.sigAlg,
        signerKeyId: decision.signerKeyId,
    };

    const signableCanon = Buffer.from(jcsCanonicalize(signable), "utf8");
    const maEdPubRaw = fromB64Url(keys.maEd25519PubRawB64Url);
    const sigBytes = fromB64Url(decision.signature);

    if (!ed25519Verify(maEdPubRaw, signableCanon, sigBytes))
        fail("Invalid signature");

    // Anti-replay
    const nonceTtlMs = 24 * 60 * 60 * 1000;
    const journal = new NonceJournalStore(NONCE_JOURNAL_FILE);
    const replayKey = `${decision.nonce}:${decision.artifactHash}`;

    if (decision.scope === "once") {
        if (journal.seen(replayKey, now, nonceTtlMs))
            fail("Replay detected (nonce already seen)");
        journal.record(replayKey, now);
        journal.compactIfNeeded(now, nonceTtlMs, 2 * 1024 * 1024);
    } else if (decision.scope !== "timebox" && decision.scope !== "session") {
        fail(`Unsupported scope: ${decision.scope}`);
    }

    console.log("✅ Decision verified and bound to artifactHash.");
    console.log(`Decision: ${decision.decision}  Scope: ${decision.scope}`);
    console.log(`ArtifactType: ${artifactWire.artifactType}`);
    console.log(`RepoRef: ${artifactWire.repoRef}`);
    console.log(`ArtifactHash: ${artifactWire.artifactHash}`);

    if (decision.decision === "allow") {
        console.log("🟢 ENFORCER RESULT: ALLOW");
        process.exit(0);
    }

    if (decision.decision === "deny") {
        console.log("🔴 ENFORCER RESULT: DENY");
        process.exit(2);
    }

    fail(`Unknown decision value: ${decision.decision}`);
}

main();
