// harp-enforcer.mjs
// HE Verifier — verifies Decision signature, binds to Artifact, enforces expiry & replay
// Mirrors Harp.Enforcer/Program.cs

import { readFileSync, existsSync } from 'node:fs';
import {
    fromB64Url, ed25519Verify,
} from './lib/crypto-helpers.mjs';
import { jcsCanonicalize } from './lib/canonical-json.mjs';
import { NonceJournalStore } from './lib/nonce-journal.mjs';

const MA_KEYS_FILE = 'C:\\tmp\\harp\\ma-keys.json';
const ARTIFACT_WIRE_FILE = 'C:\\tmp\\harp\\artifact-wire.json';
const DECISION_FILE = 'C:\\tmp\\harp\\decision.json';
const NONCE_JOURNAL_FILE = 'C:\\tmp\\harp\\nonce-journal.ndjson';

function fail(msg) {
    console.log('❌ REJECT: ' + msg);
    process.exit(1);
}

// ──────────────── Main ────────────────

if (!existsSync(MA_KEYS_FILE)) fail(`Missing ${MA_KEYS_FILE}.`);
if (!existsSync(ARTIFACT_WIRE_FILE)) fail(`Missing ${ARTIFACT_WIRE_FILE}.`);
if (!existsSync(DECISION_FILE)) fail(`Missing ${DECISION_FILE}.`);

const keys = JSON.parse(readFileSync(MA_KEYS_FILE, 'utf8'));
const maEdPubB64Url = keys.maEd25519PubRawB64Url;
const expectedSignerKeyId = keys.signerKeyId;

const artifactWire = JSON.parse(readFileSync(ARTIFACT_WIRE_FILE, 'utf8'));
const decision = JSON.parse(readFileSync(DECISION_FILE, 'utf8'));

// Basic binding
if (decision.requestId !== artifactWire.requestId)
    fail('Decision.requestId != Artifact.requestId');

if (decision.repoRef !== artifactWire.repoRef)
    fail('Decision.repoRef != Artifact.repoRef');

if (decision.artifactHashAlg !== artifactWire.artifactHashAlg)
    fail('Decision.artifactHashAlg != Artifact.artifactHashAlg');

if (decision.artifactHash.toLowerCase() !== artifactWire.artifactHash.toLowerCase())
    fail('Decision.artifactHash != Artifact.artifactHash');

// Enforce expiry
const now = new Date();
if (now > new Date(artifactWire.expiresAt))
    fail(`Artifact expired at ${artifactWire.expiresAt}`);

if (now > new Date(decision.expiresAt))
    fail(`Decision expired at ${decision.expiresAt}`);

// Signer checks
if (decision.sigAlg !== 'Ed25519')
    fail(`Unsupported sigAlg: ${decision.sigAlg}`);

if (decision.signerKeyId !== expectedSignerKeyId)
    fail(`Unknown signerKeyId: ${decision.signerKeyId}`);

// Verify signature over DecisionSignable (JCS)
const signable = {
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

const signableCanon = Buffer.from(jcsCanonicalize(signable), 'utf8');
const maEdPubRaw = fromB64Url(maEdPubB64Url);
const sigBytes = fromB64Url(decision.signature);

if (!ed25519Verify(maEdPubRaw, signableCanon, sigBytes))
    fail('Invalid signature');

// Anti-replay journal for scope=once
const nonceTtlMs = 24 * 60 * 60 * 1000; // 24 hours
const journal = new NonceJournalStore(NONCE_JOURNAL_FILE);
const replayKey = `${decision.nonce}:${decision.artifactHash}`;

if (decision.scope === 'once') {
    if (journal.seen(replayKey, now, nonceTtlMs))
        fail('Replay detected (nonce already seen)');

    journal.record(replayKey, now);
    journal.compactIfNeeded(now, nonceTtlMs, 2 * 1024 * 1024);
} else if (decision.scope === 'timebox' || decision.scope === 'session') {
    // demo policy: timebox/session rely on expiresAt; you can still optionally record nonce.
} else {
    fail(`Unsupported scope: ${decision.scope}`);
}

console.log('✅ Decision verified and bound to artifactHash.');
console.log(`Decision: ${decision.decision}  Scope: ${decision.scope}`);
console.log(`ArtifactType: ${artifactWire.artifactType}`);
console.log(`RepoRef: ${artifactWire.repoRef}`);
console.log(`ArtifactHash: ${artifactWire.artifactHash}`);

if (decision.decision === 'allow') {
    console.log('🟢 ENFORCER RESULT: ALLOW');
    process.exit(0);
}

if (decision.decision === 'deny') {
    console.log('🔴 ENFORCER RESULT: DENY');
    process.exit(2);
}

fail(`Unknown decision value: ${decision.decision}`);
