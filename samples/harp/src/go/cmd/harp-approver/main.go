// Mobile Approver — generates MA keys (first run), decrypts artifact, signs decision.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/harp-samples/go/internal/canonical"
	harpcrypto "github.com/harp-samples/go/internal/crypto"
	"github.com/harp-samples/go/internal/models"
)

const (
	maKeysFile       = `C:\tmp\harp\ma-keys.json`
	artifactWireFile = `C:\tmp\harp\artifact-wire.json`
	decisionFile     = `C:\tmp\harp\decision.json`
)

func ensureKeysExist() {
	if _, err := os.Stat(maKeysFile); err == nil {
		return
	}

	fmt.Println("Generating MA keys...")

	kxKp, err := harpcrypto.CreateX25519Keypair()
	if err != nil {
		fmt.Printf("Error creating X25519 keypair: %v\n", err)
		os.Exit(1)
	}

	signKp, err := harpcrypto.CreateEd25519Keypair()
	if err != nil {
		fmt.Printf("Error creating Ed25519 keypair: %v\n", err)
		os.Exit(1)
	}

	keys := models.MaKeys{
		MaKxPubRawB64Url:       harpcrypto.ToB64URL(kxKp.PublicKey),
		MaKxPrivRawB64Url:      harpcrypto.ToB64URL(kxKp.PrivateKey),
		MaEd25519PubRawB64Url:  harpcrypto.ToB64URL(signKp.PublicKey),
		MaEd25519PrivRawB64Url: harpcrypto.ToB64URL(signKp.PrivateKey),
		SignerKeyID:            "ma-key-1",
	}

	out, _ := json.MarshalIndent(keys, "", "  ")
	os.MkdirAll(`C:\tmp\harp`, 0755)
	os.WriteFile(maKeysFile, out, 0644)
	fmt.Printf("✅ Wrote %s\n", maKeysFile)
}

func main() {
	ensureKeysExist()

	// Load keys
	b, _ := os.ReadFile(maKeysFile)
	var keys models.MaKeys
	json.Unmarshal(b, &keys)

	maKxPrivRaw, _ := harpcrypto.FromB64URL(keys.MaKxPrivRawB64Url)
	maSignPrivRaw, _ := harpcrypto.FromB64URL(keys.MaEd25519PrivRawB64Url)
	maSignPubRaw, _ := harpcrypto.FromB64URL(keys.MaEd25519PubRawB64Url)

	if _, err := os.Stat(artifactWireFile); err != nil {
		fmt.Printf("Missing %s. Run harp-executor first.\n", artifactWireFile)
		os.Exit(0)
	}

	// Load artifact
	ab, _ := os.ReadFile(artifactWireFile)
	var artifactWire models.ArtifactWire
	json.Unmarshal(ab, &artifactWire)

	if artifactWire.Enc.EncAlg != "XChaCha20-Poly1305" {
		fmt.Printf("❌ Unsupported encAlg: %s\n", artifactWire.Enc.EncAlg)
		os.Exit(1)
	}
	if artifactWire.Enc.KDF != "X25519+HKDF-SHA256" {
		fmt.Printf("❌ Unsupported kdf: %s\n", artifactWire.Enc.KDF)
		os.Exit(1)
	}

	// Rebuild AAD
	aadObj := map[string]interface{}{
		"requestId":       artifactWire.RequestID,
		"artifactType":    artifactWire.ArtifactType,
		"repoRef":         artifactWire.RepoRef,
		"createdAt":       artifactWire.CreatedAt,
		"expiresAt":       artifactWire.ExpiresAt,
		"artifactHashAlg": artifactWire.ArtifactHashAlg,
		"artifactHash":    artifactWire.ArtifactHash,
	}
	aadStr, _ := canonical.Canonicalize(aadObj)
	aad := []byte(aadStr)

	// Key agreement + HKDF
	heKxPubRaw, _ := harpcrypto.FromB64URL(artifactWire.Enc.HeKxPub)
	sharedSecret, err := harpcrypto.X25519DeriveShared(maKxPrivRaw, heKxPubRaw)
	if err != nil {
		fmt.Printf("❌ Key agreement failed: %v\n", err)
		os.Exit(1)
	}

	salt, _ := harpcrypto.FromB64URL(artifactWire.Enc.Salt)
	info := artifactWire.Enc.Info
	if info == "" {
		info = "HARP-XCHACHA-PAYLOAD-V1"
	}
	keyMaterial, err := harpcrypto.DeriveKey(sharedSecret, salt, []byte(info), 32)
	if err != nil {
		fmt.Printf("❌ Key derivation failed: %v\n", err)
		os.Exit(1)
	}

	// AEAD decrypt
	nonce, _ := harpcrypto.FromB64URL(artifactWire.Enc.Nonce)
	ciphertext, _ := harpcrypto.FromB64URL(artifactWire.Enc.Ciphertext)
	tag, _ := harpcrypto.FromB64URL(artifactWire.Enc.Tag)

	plaintext, err := harpcrypto.XChaChaDecrypt(keyMaterial, nonce, ciphertext, tag, aad)
	if err != nil {
		fmt.Printf("❌ Decryption/auth failed: %v\n", err)
		os.Exit(1)
	}

	var payloadObj interface{}
	json.Unmarshal(plaintext, &payloadObj)

	// Verify artifactHash
	artifactWithoutHash := map[string]interface{}{
		"requestId":       artifactWire.RequestID,
		"artifactType":    artifactWire.ArtifactType,
		"repoRef":         artifactWire.RepoRef,
		"createdAt":       artifactWire.CreatedAt,
		"expiresAt":       artifactWire.ExpiresAt,
		"payload":         payloadObj,
		"artifactHashAlg": artifactWire.ArtifactHashAlg,
	}
	canonStr, _ := canonical.Canonicalize(artifactWithoutHash)
	recomputed := harpcrypto.SHA256Hex(canonStr)

	if strings.ToLower(recomputed) != strings.ToLower(artifactWire.ArtifactHash) {
		fmt.Println("❌ Hash mismatch. Refuse.")
		fmt.Printf("Expected: %s\n", artifactWire.ArtifactHash)
		fmt.Printf("Actual:   %s\n", recomputed)
		os.Exit(1)
	}

	fmt.Println("✅ Payload decrypted and artifactHash verified.")
	fmt.Println()
	fmt.Println("----- REVIEW PAYLOAD -----")
	fmt.Println(string(plaintext))
	fmt.Println("--------------------------")
	fmt.Println()

	// Prompt
	fmt.Print("Approve? (y/n): ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))

	decisionValue := "deny"
	if answer == "y" {
		decisionValue = "allow"
	}

	decisionExpires := time.Now().UTC().Add(10 * time.Minute)
	nonceBytes, _ := harpcrypto.RandomBytes(16)
	decisionNonce := harpcrypto.ToB64URL(nonceBytes)

	// Build DecisionSignable
	signable := models.DecisionSignable{
		RequestID:       artifactWire.RequestID,
		ArtifactHashAlg: artifactWire.ArtifactHashAlg,
		ArtifactHash:    artifactWire.ArtifactHash,
		RepoRef:         artifactWire.RepoRef,
		Decision:        decisionValue,
		Scope:           "once",
		ExpiresAt:       decisionExpires.Format(time.RFC3339Nano),
		Nonce:           decisionNonce,
		SigAlg:          "Ed25519",
		SignerKeyID:     keys.SignerKeyID,
	}

	signableCanon, _ := canonical.CanonicalizeBytes(signable)
	signature := harpcrypto.Ed25519Sign(ed25519.PrivateKey(maSignPrivRaw), signableCanon)

	// Self-verify
	if !harpcrypto.Ed25519Verify(ed25519.PublicKey(maSignPubRaw), signableCanon, signature) {
		fmt.Println("❌ Signature self-verify failed.")
		os.Exit(1)
	}

	decision := models.Decision{
		DecisionSignable: signable,
		Signature:        harpcrypto.ToB64URL(signature),
	}

	out, _ := json.MarshalIndent(decision, "", "  ")
	os.WriteFile(decisionFile, out, 0644)
	fmt.Printf("✅ Wrote %s (%s)\n", decisionFile, decision.Decision)
}
