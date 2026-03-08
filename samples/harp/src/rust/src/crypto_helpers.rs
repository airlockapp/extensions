//! Crypto helpers: base64url, SHA-256, HKDF, X25519, XChaCha20-Poly1305, Ed25519.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

// ──────────────── Base64url ────────────────

pub fn to_b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn from_b64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

// ──────────────── Hashing ────────────────

pub fn sha256_hex(s: &str) -> String {
    let hash = Sha256::digest(s.as_bytes());
    hex::encode(hash)
}

/// Tiny hex encoding (avoids pulling in the `hex` crate just for this).
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ──────────────── HKDF-SHA256 ────────────────

pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

// ──────────────── X25519 Key Exchange ────────────────

pub struct X25519Keypair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

pub fn create_x25519_keypair() -> X25519Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    X25519Keypair {
        public_key: *public.as_bytes(),
        private_key: secret.to_bytes(),
    }
}

pub fn x25519_derive_shared(my_private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*my_private);
    let public = X25519PublicKey::from(*peer_public);
    *secret.diffie_hellman(&public).as_bytes()
}

// ──────────────── XChaCha20-Poly1305 AEAD ────────────────

pub struct AeadResult {
    pub nonce: Vec<u8>,      // 24 bytes
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,        // 16 bytes
}

const TAG_SIZE: usize = 16;

pub fn xchacha_encrypt(key32: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<AeadResult, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key32)
        .map_err(|e| format!("xchacha new: {}", e))?;

    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let combined = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| format!("xchacha encrypt: {}", e))?;

    // Detach: split ciphertext and tag (last 16 bytes)
    let ct = combined[..combined.len() - TAG_SIZE].to_vec();
    let tag = combined[combined.len() - TAG_SIZE..].to_vec();

    Ok(AeadResult {
        nonce: nonce_bytes.to_vec(),
        ciphertext: ct,
        tag,
    })
}

pub fn xchacha_decrypt(
    key32: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new_from_slice(key32)
        .map_err(|e| format!("xchacha new: {}", e))?;

    let xnonce = XNonce::from_slice(nonce);

    // Recombine ciphertext + tag
    let mut combined = ciphertext.to_vec();
    combined.extend_from_slice(tag);

    cipher
        .decrypt(xnonce, Payload { msg: &combined, aad })
        .map_err(|e| format!("xchacha decrypt: {}", e))
}

// ──────────────── Ed25519 Signing ────────────────

pub struct Ed25519Keypair {
    pub public_key: [u8; 32],
    pub private_key: Vec<u8>, // 64 bytes (expanded) or 32 bytes (seed)
}

pub fn create_ed25519_keypair() -> Ed25519Keypair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ed25519Keypair {
        public_key: verifying_key.to_bytes(),
        private_key: signing_key.to_keypair_bytes().to_vec(), // 64 bytes
    }
}

pub fn ed25519_sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    let signing_key = if private_key.len() == 64 {
        // keypair bytes (32 seed + 32 public)
        let bytes: [u8; 64] = private_key.try_into().unwrap();
        SigningKey::from_keypair_bytes(&bytes).expect("Invalid keypair bytes")
    } else {
        // seed only (32 bytes)
        let bytes: [u8; 32] = private_key[..32].try_into().unwrap();
        SigningKey::from_bytes(&bytes)
    };
    signing_key.sign(message).to_bytes().to_vec()
}

pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message, &sig).is_ok()
}

// ──────────────── Random Bytes ────────────────

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut OsRng, &mut buf);
    buf
}
