// HE Proposer — builds & encrypts artifacts.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/harp-samples/go/internal/canonical"
	harpcrypto "github.com/harp-samples/go/internal/crypto"
	"github.com/harp-samples/go/internal/models"
)

const (
	maKeysFile       = `C:\tmp\harp\ma-keys.json`
	artifactWireFile = `C:\tmp\harp\artifact-wire.json`
)

func preview(s string) string {
	if len(s) <= 18 {
		return s
	}
	return s[:18] + "..."
}

func main() {
	b, err := os.ReadFile(maKeysFile)
	if err != nil {
		fmt.Printf("Missing %s. Run harp-approver once to generate MA keys.\n", maKeysFile)
		os.Exit(1)
	}

	var maKeys models.MaKeys
	if err := json.Unmarshal(b, &maKeys); err != nil {
		fmt.Printf("Error parsing MA keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Loaded MA public keys:")
	fmt.Printf("  MA X25519 pub: %s\n", preview(maKeys.MaKxPubRawB64Url))
	fmt.Printf("  MA Ed25519 pub: %s\n", preview(maKeys.MaEd25519PubRawB64Url))
	fmt.Printf("  signerKeyId: %s\n", maKeys.SignerKeyID)

	now := time.Now().UTC()
	expiresAt := now.Add(5 * time.Minute)

	payload := map[string]interface{}{
		"command":          `echo "hello harp"`,
		"workingDirectory": "/tmp",
		"timeoutSeconds":   10,
	}

	randBytes, _ := harpcrypto.RandomBytes(16)
	requestID := fmt.Sprintf("%x", randBytes)

	artifactWithoutHash := map[string]interface{}{
		"requestId":       requestID,
		"artifactType":    "command.review",
		"repoRef":         "repo:opaque:demo",
		"createdAt":       now.Format(time.RFC3339Nano),
		"expiresAt":       expiresAt.Format(time.RFC3339Nano),
		"payload":         payload,
		"artifactHashAlg": "SHA-256",
	}

	canonStr, err := canonical.Canonicalize(artifactWithoutHash)
	if err != nil {
		fmt.Printf("Error canonicalizing: %v\n", err)
		os.Exit(1)
	}
	artifactHashHex := harpcrypto.SHA256Hex(canonStr)

	aadObj := map[string]interface{}{
		"requestId":       requestID,
		"artifactType":    "command.review",
		"repoRef":         "repo:opaque:demo",
		"createdAt":       now.Format(time.RFC3339Nano),
		"expiresAt":       expiresAt.Format(time.RFC3339Nano),
		"artifactHashAlg": "SHA-256",
		"artifactHash":    artifactHashHex,
	}
	aadStr, _ := canonical.Canonicalize(aadObj)
	aad := []byte(aadStr)

	maKxPubRaw, _ := harpcrypto.FromB64URL(maKeys.MaKxPubRawB64Url)
	heKx, err := harpcrypto.CreateX25519Keypair()
	if err != nil {
		fmt.Printf("Error creating X25519 keypair: %v\n", err)
		os.Exit(1)
	}

	sharedSecret, err := harpcrypto.X25519DeriveShared(heKx.PrivateKey, maKxPubRaw)
	if err != nil {
		fmt.Printf("Error deriving shared secret: %v\n", err)
		os.Exit(1)
	}

	salt, _ := harpcrypto.RandomBytes(16)
	infoStr := "HARP-XCHACHA-PAYLOAD-V1"
	keyMaterial, err := harpcrypto.DeriveKey(sharedSecret, salt, []byte(infoStr), 32)
	if err != nil {
		fmt.Printf("Error deriving key: %v\n", err)
		os.Exit(1)
	}

	payloadJSON, _ := json.Marshal(payload)
	encResult, err := harpcrypto.XChaChaEncrypt(keyMaterial, payloadJSON, aad)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		os.Exit(1)
	}

	artifactWire := models.ArtifactWire{
		RequestID:       requestID,
		ArtifactType:    "command.review",
		RepoRef:         "repo:opaque:demo",
		CreatedAt:       now.Format(time.RFC3339Nano),
		ExpiresAt:       expiresAt.Format(time.RFC3339Nano),
		ArtifactHashAlg: "SHA-256",
		ArtifactHash:    artifactHashHex,
		Enc: models.EncBlob{
			KDF:        "X25519+HKDF-SHA256",
			EncAlg:     "XChaCha20-Poly1305",
			MaKxPub:    maKeys.MaKxPubRawB64Url,
			HeKxPub:    harpcrypto.ToB64URL(heKx.PublicKey),
			Salt:       harpcrypto.ToB64URL(salt),
			Info:       infoStr,
			Nonce:      harpcrypto.ToB64URL(encResult.Nonce),
			Ciphertext: harpcrypto.ToB64URL(encResult.Ciphertext),
			Tag:        harpcrypto.ToB64URL(encResult.Tag),
		},
	}

	out, _ := json.MarshalIndent(artifactWire, "", "  ")
	os.MkdirAll(`C:\tmp\harp`, 0755)
	os.WriteFile(artifactWireFile, out, 0644)

	fmt.Println()
	fmt.Println("✅ Wrote artifact-wire.json")
	fmt.Printf("artifactHash: %s\n", artifactHashHex)
}
