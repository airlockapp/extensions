//! Mobile Approver — generates MA keys (first run), decrypts artifact, signs decision.

use chrono::{Duration, Utc};
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::process;

use harp_rust::canonical_json;
use harp_rust::crypto_helpers::{
    create_ed25519_keypair, create_x25519_keypair, derive_key, ed25519_sign, ed25519_verify,
    from_b64url, random_bytes, sha256_hex, to_b64url, xchacha_decrypt,
};
use harp_rust::models::{ArtifactWire, Decision, DecisionSignable, MaKeys};

const MA_KEYS_FILE: &str = r"C:\tmp\harp\ma-keys.json";
const ARTIFACT_WIRE_FILE: &str = r"C:\tmp\harp\artifact-wire.json";
const DECISION_FILE: &str = r"C:\tmp\harp\decision.json";

fn ensure_keys_exist() {
    if fs::metadata(MA_KEYS_FILE).is_ok() {
        return;
    }

    println!("Generating MA keys...");

    let kx_kp = create_x25519_keypair();
    let sign_kp = create_ed25519_keypair();

    let keys = MaKeys {
        ma_kx_pub_raw_b64_url: to_b64url(&kx_kp.public_key),
        ma_kx_priv_raw_b64_url: to_b64url(&kx_kp.private_key),
        ma_ed25519_pub_raw_b64_url: to_b64url(&sign_kp.public_key),
        ma_ed25519_priv_raw_b64_url: to_b64url(&sign_kp.private_key),
        signer_key_id: "ma-key-1".into(),
    };

    fs::create_dir_all(r"C:\tmp\harp").ok();
    let out = serde_json::to_string_pretty(&keys).unwrap();
    fs::write(MA_KEYS_FILE, out).unwrap();
    println!("✅ Wrote {}", MA_KEYS_FILE);
}

fn main() {
    ensure_keys_exist();

    let keys: MaKeys = serde_json::from_str(&fs::read_to_string(MA_KEYS_FILE).unwrap()).unwrap();

    let ma_kx_priv_raw = from_b64url(&keys.ma_kx_priv_raw_b64_url).unwrap();
    let ma_sign_priv_raw = from_b64url(&keys.ma_ed25519_priv_raw_b64_url).unwrap();
    let ma_sign_pub_raw = from_b64url(&keys.ma_ed25519_pub_raw_b64_url).unwrap();

    if fs::metadata(ARTIFACT_WIRE_FILE).is_err() {
        println!("Missing {}. Run harp-executor first.", ARTIFACT_WIRE_FILE);
        process::exit(0);
    }

    let artifact_wire: ArtifactWire =
        serde_json::from_str(&fs::read_to_string(ARTIFACT_WIRE_FILE).unwrap()).unwrap();

    if artifact_wire.enc.enc_alg != "XChaCha20-Poly1305" {
        eprintln!("❌ Unsupported encAlg: {}", artifact_wire.enc.enc_alg);
        process::exit(1);
    }
    if artifact_wire.enc.kdf != "X25519+HKDF-SHA256" {
        eprintln!("❌ Unsupported kdf: {}", artifact_wire.enc.kdf);
        process::exit(1);
    }

    // Rebuild AAD
    let aad_obj = json!({
        "requestId": artifact_wire.request_id,
        "artifactType": artifact_wire.artifact_type,
        "repoRef": artifact_wire.repo_ref,
        "createdAt": artifact_wire.created_at,
        "expiresAt": artifact_wire.expires_at,
        "artifactHashAlg": artifact_wire.artifact_hash_alg,
        "artifactHash": artifact_wire.artifact_hash
    });
    let aad = canonical_json::canonicalize(&aad_obj).unwrap();

    // Key agreement + HKDF
    let he_kx_pub_raw = from_b64url(&artifact_wire.enc.he_kx_pub).unwrap();
    let mut my_priv = [0u8; 32];
    my_priv.copy_from_slice(&ma_kx_priv_raw);
    let mut peer_pub = [0u8; 32];
    peer_pub.copy_from_slice(&he_kx_pub_raw);
    let shared_secret = harp_rust::crypto_helpers::x25519_derive_shared(&my_priv, &peer_pub);

    let salt = from_b64url(&artifact_wire.enc.salt).unwrap();
    let info = if artifact_wire.enc.info.is_empty() {
        "HARP-XCHACHA-PAYLOAD-V1"
    } else {
        &artifact_wire.enc.info
    };
    let key_material = derive_key(&shared_secret, &salt, info.as_bytes(), 32);

    // AEAD decrypt
    let nonce = from_b64url(&artifact_wire.enc.nonce).unwrap();
    let ciphertext = from_b64url(&artifact_wire.enc.ciphertext).unwrap();
    let tag = from_b64url(&artifact_wire.enc.tag).unwrap();

    let plaintext = match xchacha_decrypt(&key_material, &nonce, &ciphertext, &tag, aad.as_bytes())
    {
        Ok(pt) => pt,
        Err(e) => {
            eprintln!("❌ Decryption/auth failed: {}", e);
            process::exit(1);
        }
    };

    let payload_json = String::from_utf8(plaintext).unwrap();
    let payload_obj: serde_json::Value = serde_json::from_str(&payload_json).unwrap();

    // Verify artifactHash
    let artifact_without_hash = json!({
        "requestId": artifact_wire.request_id,
        "artifactType": artifact_wire.artifact_type,
        "repoRef": artifact_wire.repo_ref,
        "createdAt": artifact_wire.created_at,
        "expiresAt": artifact_wire.expires_at,
        "payload": payload_obj,
        "artifactHashAlg": artifact_wire.artifact_hash_alg
    });

    let canon_str = canonical_json::canonicalize(&artifact_without_hash).unwrap();
    let recomputed = sha256_hex(&canon_str);

    if recomputed.to_lowercase() != artifact_wire.artifact_hash.to_lowercase() {
        eprintln!("❌ Hash mismatch. Refuse.");
        eprintln!("Expected: {}", artifact_wire.artifact_hash);
        eprintln!("Actual:   {}", recomputed);
        process::exit(1);
    }

    println!("✅ Payload decrypted and artifactHash verified.");
    println!();
    println!("----- REVIEW PAYLOAD -----");
    println!("{}", payload_json);
    println!("--------------------------");
    println!();

    print!("Approve? (y/n): ");
    io::stdout().flush().unwrap();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap();
    let decision_value = if answer.trim().to_lowercase() == "y" {
        "allow"
    } else {
        "deny"
    };

    let decision_expires = Utc::now() + Duration::minutes(10);
    let decision_nonce = to_b64url(&random_bytes(16));

    let signable = DecisionSignable {
        request_id: artifact_wire.request_id.clone(),
        artifact_hash_alg: artifact_wire.artifact_hash_alg.clone(),
        artifact_hash: artifact_wire.artifact_hash.clone(),
        repo_ref: artifact_wire.repo_ref.clone(),
        decision: decision_value.into(),
        scope: "once".into(),
        expires_at: decision_expires.to_rfc3339(),
        nonce: decision_nonce,
        sig_alg: "Ed25519".into(),
        signer_key_id: keys.signer_key_id.clone(),
    };

    let signable_canon = canonical_json::canonicalize_bytes(&signable).unwrap();
    let signature = ed25519_sign(&ma_sign_priv_raw, &signable_canon);

    // Self-verify
    if !ed25519_verify(&ma_sign_pub_raw, &signable_canon, &signature) {
        eprintln!("❌ Signature self-verify failed.");
        process::exit(1);
    }

    let decision = Decision {
        request_id: signable.request_id,
        artifact_hash_alg: signable.artifact_hash_alg,
        artifact_hash: signable.artifact_hash,
        repo_ref: signable.repo_ref,
        decision: signable.decision.clone(),
        scope: signable.scope,
        expires_at: signable.expires_at,
        nonce: signable.nonce,
        sig_alg: signable.sig_alg,
        signer_key_id: signable.signer_key_id,
        signature: to_b64url(&signature),
    };

    let out = serde_json::to_string_pretty(&decision).unwrap();
    fs::write(DECISION_FILE, out).unwrap();
    println!("✅ Wrote {} ({})", DECISION_FILE, decision.decision);
}
