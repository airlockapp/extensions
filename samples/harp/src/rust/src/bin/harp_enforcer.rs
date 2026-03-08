//! HE Verifier — verifies Decision signature, binds to Artifact, enforces expiry & replay.

use chrono::{DateTime, Duration, Utc};
use std::fs;
use std::process;

use harp_rust::canonical_json;
use harp_rust::crypto_helpers::{ed25519_verify, from_b64url};
use harp_rust::models::{ArtifactWire, Decision, MaKeys};
use harp_rust::nonce_journal::NonceJournalStore;

const MA_KEYS_FILE: &str = r"C:\tmp\harp\ma-keys.json";
const ARTIFACT_WIRE_FILE: &str = r"C:\tmp\harp\artifact-wire.json";
const DECISION_FILE: &str = r"C:\tmp\harp\decision.json";
const NONCE_JOURNAL_FILE: &str = r"C:\tmp\harp\nonce-journal.ndjson";

fn fail(msg: &str) -> ! {
    println!("❌ REJECT: {}", msg);
    process::exit(1);
}

fn main() {
    let keys: MaKeys = match fs::read_to_string(MA_KEYS_FILE) {
        Ok(d) => serde_json::from_str(&d).unwrap(),
        Err(_) => fail(&format!("Missing {}.", MA_KEYS_FILE)),
    };
    let artifact_wire: ArtifactWire = match fs::read_to_string(ARTIFACT_WIRE_FILE) {
        Ok(d) => serde_json::from_str(&d).unwrap(),
        Err(_) => fail(&format!("Missing {}.", ARTIFACT_WIRE_FILE)),
    };
    let decision: Decision = match fs::read_to_string(DECISION_FILE) {
        Ok(d) => serde_json::from_str(&d).unwrap(),
        Err(_) => fail(&format!("Missing {}.", DECISION_FILE)),
    };

    // Binding checks
    if decision.request_id != artifact_wire.request_id {
        fail("Decision.requestId != Artifact.requestId");
    }
    if decision.repo_ref != artifact_wire.repo_ref {
        fail("Decision.repoRef != Artifact.repoRef");
    }
    if decision.artifact_hash_alg != artifact_wire.artifact_hash_alg {
        fail("Decision.artifactHashAlg != Artifact.artifactHashAlg");
    }
    if decision.artifact_hash.to_lowercase() != artifact_wire.artifact_hash.to_lowercase() {
        fail("Decision.artifactHash != Artifact.artifactHash");
    }

    // Expiry checks
    let now = Utc::now();
    let artifact_expires: DateTime<Utc> = artifact_wire
        .expires_at
        .parse::<DateTime<chrono::FixedOffset>>()
        .unwrap_or_else(|_| fail(&format!("Invalid artifact expiresAt: {}", artifact_wire.expires_at)))
        .with_timezone(&Utc);
    if now > artifact_expires {
        fail(&format!("Artifact expired at {}", artifact_wire.expires_at));
    }

    let decision_expires: DateTime<Utc> = decision
        .expires_at
        .parse::<DateTime<chrono::FixedOffset>>()
        .unwrap_or_else(|_| fail(&format!("Invalid decision expiresAt: {}", decision.expires_at)))
        .with_timezone(&Utc);
    if now > decision_expires {
        fail(&format!("Decision expired at {}", decision.expires_at));
    }

    // Signer checks
    if decision.sig_alg != "Ed25519" {
        fail(&format!("Unsupported sigAlg: {}", decision.sig_alg));
    }
    if decision.signer_key_id != keys.signer_key_id {
        fail(&format!("Unknown signerKeyId: {}", decision.signer_key_id));
    }

    // Verify signature
    let signable = decision.to_signable();
    let signable_canon = canonical_json::canonicalize_bytes(&signable).unwrap();
    let ma_ed_pub_raw = from_b64url(&keys.ma_ed25519_pub_raw_b64_url).unwrap();
    let sig_bytes = from_b64url(&decision.signature).unwrap();

    if !ed25519_verify(&ma_ed_pub_raw, &signable_canon, &sig_bytes) {
        fail("Invalid signature");
    }

    // Anti-replay
    let nonce_ttl = Duration::hours(24);
    let mut journal =
        NonceJournalStore::new(NONCE_JOURNAL_FILE).expect("Failed to open nonce journal");
    let replay_key = format!("{}:{}", decision.nonce, decision.artifact_hash);

    match decision.scope.as_str() {
        "once" => {
            if journal.seen(&replay_key, now, nonce_ttl) {
                fail("Replay detected (nonce already seen)");
            }
            journal.record(&replay_key, now).expect("Journal record failed");
            journal
                .compact_if_needed(now, nonce_ttl, 2 * 1024 * 1024)
                .ok();
        }
        "timebox" | "session" => {
            // rely on expiresAt
        }
        _ => fail(&format!("Unsupported scope: {}", decision.scope)),
    }

    println!("✅ Decision verified and bound to artifactHash.");
    println!("Decision: {}  Scope: {}", decision.decision, decision.scope);
    println!("ArtifactType: {}", artifact_wire.artifact_type);
    println!("RepoRef: {}", artifact_wire.repo_ref);
    println!("ArtifactHash: {}", artifact_wire.artifact_hash);

    match decision.decision.as_str() {
        "allow" => {
            println!("🟢 ENFORCER RESULT: ALLOW");
            process::exit(0);
        }
        "deny" => {
            println!("🔴 ENFORCER RESULT: DENY");
            process::exit(2);
        }
        _ => fail(&format!("Unknown decision value: {}", decision.decision)),
    }
}
