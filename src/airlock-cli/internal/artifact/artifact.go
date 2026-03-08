package artifact

import (
	"encoding/json"
	"time"

	"github.com/airlock/airlock-cli/internal/crypto"
)

// ApprovePayload is the plaintext content encrypted and sent inside the artifact (command-approval).
type ApprovePayload struct {
	ActionType string `json:"actionType"`
	CommandText string `json:"commandText"`
	ButtonText  string `json:"buttonText"`
	Workspace   string `json:"workspace"`
	RepoName    string `json:"repoName"`
	Source      string `json:"source"`
	Shell       string `json:"shell,omitempty"`
	Cwd         string `json:"cwd,omitempty"`
	SessionID   string `json:"sessionId,omitempty"`
	ShellPid    string `json:"shellPid,omitempty"`
	Host        string `json:"host,omitempty"`
}

// BuildEnvelope builds the artifact.submit envelope for the gateway.
// encryptionKey is raw 32-byte AES key; metadata must include routingToken and workspaceName.
func BuildEnvelope(
	requestID, enforcerID string,
	payload *ApprovePayload,
	encryptionKey []byte,
	routingToken, workspaceName string,
) (interface{}, string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}

	dataB64, nonceB64, tagB64, err := crypto.AESGCMEncrypt(encryptionKey, plaintext)
	if err != nil {
		return nil, "", err
	}

	now := time.Now().UnixMilli()
	artifactHash := crypto.ArtifactHash("command-approval", payload.CommandText, now)
	expiresAt := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)

	metadata := map[string]string{
		"workspaceName": workspaceName,
		"repoName":      payload.RepoName,
	}
	if routingToken != "" {
		metadata["routingToken"] = routingToken
	}

	body := map[string]interface{}{
		"artifactType": "command-approval",
		"artifactHash": artifactHash,
		"ciphertext": map[string]string{
			"alg":   "AES-256-GCM",
			"data":  dataB64,
			"nonce": nonceB64,
			"tag":   tagB64,
		},
		"expiresAt": expiresAt,
		"metadata":  metadata,
	}

	envelope := map[string]interface{}{
		"msgId":     "msg-" + requestID,
		"msgType":   "artifact.submit",
		"requestId": requestID,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
		"sender": map[string]string{
			"enforcerId": enforcerID,
		},
		"body": body,
	}
	return envelope, artifactHash, nil
}
