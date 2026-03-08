//! Data models for the HARP protocol wire types.

use serde::{Deserialize, Serialize};

/// Encrypted blob containing all information needed to decrypt the artifact payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncBlob {
    pub kdf: String,
    pub enc_alg: String,
    pub ma_kx_pub: String,
    pub he_kx_pub: String,
    pub salt: String,
    pub info: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
}

/// Artifact as transmitted over the wire (encrypted payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactWire {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub artifact_type: String,
    pub repo_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub artifact_hash_alg: String,
    pub artifact_hash: String,
    pub enc: EncBlob,
}

/// Decision token fields that are signed (everything except signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionSignable {
    pub request_id: String,
    pub artifact_hash_alg: String,
    pub artifact_hash: String,
    pub repo_ref: String,
    pub decision: String,
    pub scope: String,
    pub expires_at: String,
    pub nonce: String,
    pub sig_alg: String,
    pub signer_key_id: String,
}

/// Complete decision token including signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub request_id: String,
    pub artifact_hash_alg: String,
    pub artifact_hash: String,
    pub repo_ref: String,
    pub decision: String,
    pub scope: String,
    pub expires_at: String,
    pub nonce: String,
    pub sig_alg: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl Decision {
    /// Extract the signable portion (everything except signature).
    pub fn to_signable(&self) -> DecisionSignable {
        DecisionSignable {
            request_id: self.request_id.clone(),
            artifact_hash_alg: self.artifact_hash_alg.clone(),
            artifact_hash: self.artifact_hash.clone(),
            repo_ref: self.repo_ref.clone(),
            decision: self.decision.clone(),
            scope: self.scope.clone(),
            expires_at: self.expires_at.clone(),
            nonce: self.nonce.clone(),
            sig_alg: self.sig_alg.clone(),
            signer_key_id: self.signer_key_id.clone(),
        }
    }
}

/// MA key material stored in ma-keys.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaKeys {
    pub ma_kx_pub_raw_b64_url: String,
    pub ma_kx_priv_raw_b64_url: String,
    pub ma_ed25519_pub_raw_b64_url: String,
    pub ma_ed25519_priv_raw_b64_url: String,
    pub signer_key_id: String,
}
