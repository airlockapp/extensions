// Package models defines the wire types for the HARP protocol.
package models

// EncBlob contains all information needed to decrypt the artifact payload.
type EncBlob struct {
	KDF        string `json:"kdf"`        // "X25519+HKDF-SHA256"
	EncAlg     string `json:"encAlg"`     // "XChaCha20-Poly1305"
	MaKxPub    string `json:"maKxPub"`    // base64url
	HeKxPub    string `json:"heKxPub"`    // base64url
	Salt       string `json:"salt"`       // base64url (16 bytes)
	Info       string `json:"info"`       // "HARP-XCHACHA-PAYLOAD-V1"
	Nonce      string `json:"nonce"`      // base64url (24 bytes)
	Ciphertext string `json:"ciphertext"` // base64url
	Tag        string `json:"tag"`        // base64url (16 bytes)
}

// ArtifactWire is the artifact as transmitted over the wire (encrypted payload).
type ArtifactWire struct {
	RequestID       string                 `json:"requestId"`
	SessionID       string                 `json:"sessionId,omitempty"`
	ArtifactType    string                 `json:"artifactType"`
	RepoRef         string                 `json:"repoRef"`
	BaseRevision    string                 `json:"baseRevision,omitempty"`
	CreatedAt       string                 `json:"createdAt"`
	ExpiresAt       string                 `json:"expiresAt"`
	ArtifactHashAlg string                 `json:"artifactHashAlg"`
	ArtifactHash    string                 `json:"artifactHash"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	Extensions      map[string]interface{} `json:"extensions,omitempty"`
	Enc             EncBlob                `json:"enc"`
}

// DecisionSignable contains the fields that are signed (everything except signature).
type DecisionSignable struct {
	RequestID       string `json:"requestId"`
	ArtifactHashAlg string `json:"artifactHashAlg"`
	ArtifactHash    string `json:"artifactHash"`
	RepoRef         string `json:"repoRef"`
	Decision        string `json:"decision"` // "allow" or "deny"
	Scope           string `json:"scope"`    // "once", "timebox", "session"
	ExpiresAt       string `json:"expiresAt"`
	Nonce           string `json:"nonce"`
	SigAlg          string `json:"sigAlg"` // "Ed25519"
	SignerKeyID     string `json:"signerKeyId"`
}

// Decision is the complete decision token including signature.
type Decision struct {
	DecisionSignable
	Signature string `json:"signature"` // base64url
}

// MaKeys is the MA key material stored in ma-keys.json.
type MaKeys struct {
	MaKxPubRawB64Url       string `json:"maKxPubRawB64Url"`
	MaKxPrivRawB64Url      string `json:"maKxPrivRawB64Url"`
	MaEd25519PubRawB64Url  string `json:"maEd25519PubRawB64Url"`
	MaEd25519PrivRawB64Url string `json:"maEd25519PrivRawB64Url"`
	SignerKeyID            string `json:"signerKeyId"`
}
