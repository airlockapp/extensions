// HE Verifier — verifies Decision signature, binds to Artifact, enforces expiry & replay.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/harp-samples/go/internal/canonical"
	harpcrypto "github.com/harp-samples/go/internal/crypto"
	"github.com/harp-samples/go/internal/journal"
	"github.com/harp-samples/go/internal/models"
)

const (
	maKeysFile       = `C:\tmp\harp\ma-keys.json`
	artifactWireFile = `C:\tmp\harp\artifact-wire.json`
	decisionFile     = `C:\tmp\harp\decision.json`
	nonceJournalFile = `C:\tmp\harp\nonce-journal.ndjson`
)

func fail(msg string) {
	fmt.Println("❌ REJECT: " + msg)
	os.Exit(1)
}

func main() {
	// Load files
	kb, err := os.ReadFile(maKeysFile)
	if err != nil {
		fail(fmt.Sprintf("Missing %s.", maKeysFile))
	}
	ab, err := os.ReadFile(artifactWireFile)
	if err != nil {
		fail(fmt.Sprintf("Missing %s.", artifactWireFile))
	}
	db, err := os.ReadFile(decisionFile)
	if err != nil {
		fail(fmt.Sprintf("Missing %s.", decisionFile))
	}

	var keys models.MaKeys
	var artifactWire models.ArtifactWire
	var decision models.Decision

	json.Unmarshal(kb, &keys)
	json.Unmarshal(ab, &artifactWire)
	json.Unmarshal(db, &decision)

	// Binding checks
	if decision.RequestID != artifactWire.RequestID {
		fail("Decision.requestId != Artifact.requestId")
	}
	if decision.RepoRef != artifactWire.RepoRef {
		fail("Decision.repoRef != Artifact.repoRef")
	}
	if decision.ArtifactHashAlg != artifactWire.ArtifactHashAlg {
		fail("Decision.artifactHashAlg != Artifact.artifactHashAlg")
	}
	if strings.ToLower(decision.ArtifactHash) != strings.ToLower(artifactWire.ArtifactHash) {
		fail("Decision.artifactHash != Artifact.artifactHash")
	}

	// Expiry checks
	now := time.Now().UTC()
	artifactExpires, _ := time.Parse(time.RFC3339Nano, artifactWire.ExpiresAt)
	if now.After(artifactExpires) {
		fail(fmt.Sprintf("Artifact expired at %s", artifactWire.ExpiresAt))
	}
	decisionExpires, _ := time.Parse(time.RFC3339Nano, decision.ExpiresAt)
	if now.After(decisionExpires) {
		fail(fmt.Sprintf("Decision expired at %s", decision.ExpiresAt))
	}

	// Signer checks
	if decision.SigAlg != "Ed25519" {
		fail(fmt.Sprintf("Unsupported sigAlg: %s", decision.SigAlg))
	}
	if decision.SignerKeyID != keys.SignerKeyID {
		fail(fmt.Sprintf("Unknown signerKeyId: %s", decision.SignerKeyID))
	}

	// Verify signature
	signable := models.DecisionSignable{
		RequestID:       decision.RequestID,
		ArtifactHashAlg: decision.ArtifactHashAlg,
		ArtifactHash:    decision.ArtifactHash,
		RepoRef:         decision.RepoRef,
		Decision:        decision.Decision,
		Scope:           decision.Scope,
		ExpiresAt:       decision.ExpiresAt,
		Nonce:           decision.Nonce,
		SigAlg:          decision.SigAlg,
		SignerKeyID:     decision.SignerKeyID,
	}

	signableCanon, _ := canonical.CanonicalizeBytes(signable)
	maEdPubRaw, _ := harpcrypto.FromB64URL(keys.MaEd25519PubRawB64Url)
	sigBytes, _ := harpcrypto.FromB64URL(decision.Signature)

	if !harpcrypto.Ed25519Verify(ed25519.PublicKey(maEdPubRaw), signableCanon, sigBytes) {
		fail("Invalid signature")
	}

	// Anti-replay
	nonceTTL := 24 * time.Hour
	j, err := journal.New(nonceJournalFile)
	if err != nil {
		fail(fmt.Sprintf("Journal error: %v", err))
	}
	replayKey := fmt.Sprintf("%s:%s", decision.Nonce, decision.ArtifactHash)

	switch decision.Scope {
	case "once":
		if j.Seen(replayKey, now, nonceTTL) {
			fail("Replay detected (nonce already seen)")
		}
		if err := j.Record(replayKey, now); err != nil {
			fail(fmt.Sprintf("Journal record error: %v", err))
		}
		j.CompactIfNeeded(now, nonceTTL, 2*1024*1024)
	case "timebox", "session":
		// rely on expiresAt
	default:
		fail(fmt.Sprintf("Unsupported scope: %s", decision.Scope))
	}

	fmt.Println("✅ Decision verified and bound to artifactHash.")
	fmt.Printf("Decision: %s  Scope: %s\n", decision.Decision, decision.Scope)
	fmt.Printf("ArtifactType: %s\n", artifactWire.ArtifactType)
	fmt.Printf("RepoRef: %s\n", artifactWire.RepoRef)
	fmt.Printf("ArtifactHash: %s\n", artifactWire.ArtifactHash)

	switch decision.Decision {
	case "allow":
		fmt.Println("🟢 ENFORCER RESULT: ALLOW")
		os.Exit(0)
	case "deny":
		fmt.Println("🔴 ENFORCER RESULT: DENY")
		os.Exit(2)
	default:
		fail(fmt.Sprintf("Unknown decision value: %s", decision.Decision))
	}
}
