package pairing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/airlock/airlock-cli/internal/crypto"
	"github.com/airlock/airlock-cli/internal/store"
)

// InitiateRequest is the body for POST /v1/pairing/initiate.
type InitiateRequest struct {
	DeviceID        string `json:"deviceId"`
	EnforcerID      string `json:"enforcerId"`
	GatewayURL      string `json:"gatewayUrl,omitempty"`
	EnforcerLabel   string `json:"enforcerLabel,omitempty"`
	WorkspaceName   string `json:"workspaceName,omitempty"`
	X25519PublicKey string `json:"x25519PublicKey,omitempty"`
}

// InitiateResponse is the response from initiate.
type InitiateResponse struct {
	PairingNonce string    `json:"pairingNonce"`
	PairingCode  string    `json:"pairingCode"`
	DeviceID     string    `json:"deviceId"`
	GatewayURL   string    `json:"gatewayUrl"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// StatusResponse is the response from GET /v1/pairing/{nonce}/status.
type StatusResponse struct {
	PairingNonce string `json:"pairingNonce"`
	State        string `json:"state"`
	ResponseJSON string `json:"responseJson,omitempty"`
	RoutingToken string `json:"routingToken,omitempty"`
	ExpiresAt    string `json:"expiresAt"`
}

// PairingResponseJSON is the mobile-sent responseJson (signerKeyId, publicKey, x25519PublicKey, etc.).
type PairingResponseJSON struct {
	SignerKeyID    string `json:"signerKeyId"`
	PublicKey      string `json:"publicKey"`
	PairingNonce   string `json:"pairingNonce"`
	Timestamp      string `json:"timestamp"`
	Signature      string `json:"signature"`
	X25519PublicKey string `json:"x25519PublicKey,omitempty"`
}

// Initiate starts a pairing session. Caller must pass a valid access token.
func Initiate(baseURL, token, deviceID, enforcerID, enforcerLabel, workspaceName string, x25519PubB64 string) (*InitiateResponse, error) {
	body := InitiateRequest{
		DeviceID:        deviceID,
		EnforcerID:      enforcerID,
		GatewayURL:      baseURL,
		EnforcerLabel:   enforcerLabel,
		WorkspaceName:   workspaceName,
		X25519PublicKey: x25519PubB64,
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/pairing/initiate", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("initiate failed: %d", resp.StatusCode)
	}

	var out InitiateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status polls pairing status.
func Status(baseURL, token, nonce string) (*StatusResponse, error) {
	url := baseURL + "/v1/pairing/" + nonce + "/status"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status failed: %d", resp.StatusCode)
	}

	var out StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CompletePairing parses responseJson, derives shared key, and fills secrets.
// Call after Status returns state=Completed. localX25519PrivateKey is raw 32-byte private key.
func CompletePairing(responseJSON, routingToken string, localX25519PrivateKey []byte) (encryptionKeyB64 string, pairedKeys map[string]string, err error) {
	var pr PairingResponseJSON
	if err := json.Unmarshal([]byte(responseJSON), &pr); err != nil {
		return "", nil, fmt.Errorf("parse responseJson: %w", err)
	}

	pairedKeys = make(map[string]string)
	pairedKeys[pr.SignerKeyID] = pr.PublicKey
	// Also store with key- prefix for lookup
	pairedKeys["key-"+pr.SignerKeyID] = pr.PublicKey

	if pr.X25519PublicKey == "" {
		return "", nil, fmt.Errorf("mobile did not send x25519PublicKey (old app?)")
	}

	// Mobile sends unpadded base64url (43 chars for 32-byte key); use flexible decoder
	remotePub, err := crypto.DecodeBase64URLFlexible(pr.X25519PublicKey)
	if err != nil {
		return "", nil, fmt.Errorf("decode mobile x25519 public key: %w", err)
	}
	// Decoder may return 33 bytes (trailing zero from padding); X25519 needs exactly 32
	if len(remotePub) == 33 && remotePub[32] == 0 {
		remotePub = remotePub[:32]
	}
	if len(remotePub) != 32 {
		return "", nil, fmt.Errorf("mobile x25519 public key must be 32 bytes, got %d", len(remotePub))
	}

	sharedKey, err := crypto.DeriveSharedKey(localX25519PrivateKey, remotePub)
	if err != nil {
		return "", nil, fmt.Errorf("derive shared key: %w", err)
	}

	encryptionKeyB64 = base64.RawURLEncoding.EncodeToString(sharedKey)
	return encryptionKeyB64, pairedKeys, nil
}

// NormalizeGatewayURL trims trailing slash.
func NormalizeGatewayURL(url string) string {
	return store.NormalizeGatewayURL(url)
}
