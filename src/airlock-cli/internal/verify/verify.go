package verify

import (
	"fmt"
	"strings"

	"github.com/airlock/airlock-cli/internal/crypto"
)

// DecisionOutcome is the result of verifying a decision.deliver body.
type DecisionOutcome struct {
	Approved bool
	Reason   string
	Error    string
}

// VerifyDecision checks Ed25519 signature and returns approved/denied.
// Body is the "body" of decision.deliver (artifactHash, decision, reason, signerKeyId, nonce, signature).
// pairedKeys maps signerKeyId -> base64 Ed25519 public key.
func VerifyDecision(body map[string]interface{}, expectedArtifactHash string, pairedKeys map[string]string) DecisionOutcome {
	decision, _ := body["decision"].(string)
	if decision == "" {
		if d, ok := body["Decision"].(string); ok {
			decision = d
		}
	}
	decision = strings.ToLower(strings.TrimSpace(decision))
	if decision != "approve" && decision != "reject" {
		return DecisionOutcome{Error: "invalid decision value"}
	}

	artifactHash, _ := body["artifactHash"].(string)
	if artifactHash == "" {
		artifactHash, _ = body["ArtifactHash"].(string)
	}
	if artifactHash != expectedArtifactHash {
		return DecisionOutcome{Error: "artifactHash mismatch"}
	}

	nonce, _ := body["nonce"].(string)
	if nonce == "" {
		nonce, _ = body["Nonce"].(string)
	}
	signature, _ := body["signature"].(string)
	if signature == "" {
		signature, _ = body["Signature"].(string)
	}
	signerKeyId, _ := body["signerKeyId"].(string)
	if signerKeyId == "" {
		signerKeyId, _ = body["SignerKeyId"].(string)
	}

	if signerKeyId == "" || signature == "" || nonce == "" {
		return DecisionOutcome{Error: "missing signature fields (signerKeyId, signature, nonce)"}
	}

	pubB64 := pairedKeys[signerKeyId]
	if pubB64 == "" {
		pubB64 = pairedKeys["key-"+signerKeyId]
	}
	if pubB64 == "" {
		for k, v := range pairedKeys {
			if k == signerKeyId || k == "key-"+signerKeyId {
				pubB64 = v
				break
			}
		}
	}
	if pubB64 == "" {
		return DecisionOutcome{Error: fmt.Sprintf("unknown signerKeyId: %s", signerKeyId)}
	}

	pubKey, err := crypto.DecodeBase64PublicKey(pubB64)
	if err != nil {
		return DecisionOutcome{Error: "invalid paired public key: " + err.Error()}
	}

	sigBytes, err := crypto.DecodeBase64Signature(signature)
	if err != nil {
		return DecisionOutcome{Error: "invalid signature encoding: " + err.Error()}
	}

	canonical := artifactHash + "|" + decision + "|" + nonce
	if !crypto.Ed25519Verify(pubKey, []byte(canonical), sigBytes) {
		return DecisionOutcome{Error: "signature verification failed"}
	}

	reason, _ := body["reason"].(string)
	if reason == "" {
		reason, _ = body["Reason"].(string)
	}
	return DecisionOutcome{
		Approved: decision == "approve",
		Reason:   reason,
	}
}