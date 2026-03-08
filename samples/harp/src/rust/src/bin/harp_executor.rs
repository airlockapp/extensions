//! HE Proposer — builds & encrypts artifacts.

use chrono::{Duration, Utc};
use serde_json::json;
use std::fs;
use std::process;

use harp_rust::canonical_json;
use harp_rust::crypto_helpers::{
    create_x25519_keypair, derive_key, from_b64url, random_bytes, sha256_hex, to_b64url,
    xchacha_encrypt,
};
use harp_rust::models::{ArtifactWire, EncBlob, MaKeys};

const MA_KEYS_FILE: &str = r"C:\tmp\harp\ma-keys.json";
const ARTIFACT_WIRE_FILE: &str = r"C:\tmp\harp\artifact-wire.json";

fn preview(s: &str) -> String {
    if s.len() <= 18 {
        s.to_string()
    } else {
        format!("{}...", &s[..18])
    }
}

fn main() {
    // Load MA keys
    let data = match fs::read_to_string(MA_KEYS_FILE) {
        Ok(d) => d,
        Err(_) => {
            println!("Missing {}. Run harp-approver once to generate MA keys.", MA_KEYS_FILE);
            process::exit(1);
        }
    };
    let ma_keys: MaKeys = serde_json::from_str(&data).unwrap();

    println!("Loaded MA public keys:");
    println!("  MA X25519 pub: {}", preview(&ma_keys.ma_kx_pub_raw_b64_url));
    println!("  MA Ed25519 pub: {}", preview(&ma_keys.ma_ed25519_pub_raw_b64_url));
    println!("  signerKeyId: {}", ma_keys.signer_key_id);

    let now = Utc::now();
    let expires_at = now + Duration::minutes(5);

    // Payload
    let payload = json!({
        "command": "echo \"hello harp\"",
        "workingDirectory": "/tmp",
        "timeoutSeconds": 10
    });

    let request_id = hex_encode(&random_bytes(16));

    // Build artifact-without-hash
    let artifact_without_hash = json!({
        "requestId": request_id,
        "artifactType": "command.review",
        "repoRef": "repo:opaque:demo",
        "createdAt": now.to_rfc3339(),
        "expiresAt": expires_at.to_rfc3339(),
        "payload": payload,
        "artifactHashAlg": "SHA-256"
    });

    let canon_str = canonical_json::canonicalize(&artifact_without_hash).unwrap();
    let artifact_hash_hex = sha256_hex(&canon_str);

    // Build AAD
    let aad_obj = json!({
        "requestId": request_id,
        "artifactType": "command.review",
        "repoRef": "repo:opaque:demo",
        "createdAt": now.to_rfc3339(),
        "expiresAt": expires_at.to_rfc3339(),
        "artifactHashAlg": "SHA-256",
        "artifactHash": artifact_hash_hex
    });
    let aad = canonical_json::canonicalize(&aad_obj).unwrap();

    // Key agreement
    let ma_kx_pub_raw = from_b64url(&ma_keys.ma_kx_pub_raw_b64_url).unwrap();
    let he_kx = create_x25519_keypair();
    let mut peer_pub = [0u8; 32];
    peer_pub.copy_from_slice(&ma_kx_pub_raw);
    let shared_secret = harp_rust::crypto_helpers::x25519_derive_shared(&he_kx.private_key, &peer_pub);

    // HKDF
    let salt = random_bytes(16);
    let info_str = "HARP-XCHACHA-PAYLOAD-V1";
    let key_material = derive_key(&shared_secret, &salt, info_str.as_bytes(), 32);

    // AEAD encrypt
    let payload_json = serde_json::to_string(&payload).unwrap();
    let enc_result = xchacha_encrypt(&key_material, payload_json.as_bytes(), aad.as_bytes())
        .expect("Encryption failed");

    let artifact_wire = ArtifactWire {
        request_id: request_id.clone(),
        session_id: None,
        artifact_type: "command.review".into(),
        repo_ref: "repo:opaque:demo".into(),
        base_revision: None,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        artifact_hash_alg: "SHA-256".into(),
        artifact_hash: artifact_hash_hex.clone(),
        enc: EncBlob {
            kdf: "X25519+HKDF-SHA256".into(),
            enc_alg: "XChaCha20-Poly1305".into(),
            ma_kx_pub: ma_keys.ma_kx_pub_raw_b64_url.clone(),
            he_kx_pub: to_b64url(&he_kx.public_key),
            salt: to_b64url(&salt),
            info: info_str.into(),
            nonce: to_b64url(&enc_result.nonce),
            ciphertext: to_b64url(&enc_result.ciphertext),
            tag: to_b64url(&enc_result.tag),
        },
    };

    fs::create_dir_all(r"C:\tmp\harp").ok();
    let out = serde_json::to_string_pretty(&artifact_wire).unwrap();
    fs::write(ARTIFACT_WIRE_FILE, out).unwrap();

    println!();
    println!("✅ Wrote artifact-wire.json");
    println!("artifactHash: {}", artifact_hash_hex);
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
