package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/airlock/airlock-cli/internal/store"
)

const (
	deviceAuthPath   = "/v1/auth/device"
	deviceTokenPath  = "/v1/auth/device/token"
	refreshPath      = "/v1/auth/refresh"
	refreshThreshold = 60 * time.Second // refresh if exp is within 60s
)

// DeviceAuthStartResponse is the response from POST /v1/auth/device.
type DeviceAuthStartResponse struct {
	DeviceCode             string `json:"deviceCode"`
	UserCode               string `json:"userCode"`
	VerificationURI        string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn              int    `json:"expiresIn"`
	Interval               int    `json:"interval"`
}

// DeviceTokenResponse is the response from POST /v1/auth/device/token.
type DeviceTokenResponse struct {
	Completed    bool   `json:"completed"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	ExpiresIn    int    `json:"expiresIn,omitempty"`
	Error        string `json:"error,omitempty"`
}

// RefreshResponse is the response from POST /v1/auth/refresh.
type RefreshResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int    `json:"expiresIn"`
}

// Client performs auth against the gateway (proxied to backend).
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates an auth client for the given gateway base URL.
func NewClient(gatewayURL string) *Client {
	return &Client{
		baseURL:    store.NormalizeGatewayURL(gatewayURL),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// StartDeviceAuth starts the device authorization flow. Returns user code and URL to open.
func (c *Client) StartDeviceAuth() (*DeviceAuthStartResponse, error) {
	body := bytes.NewReader([]byte("{}"))
	req, err := http.NewRequest(http.MethodPost, c.baseURL+deviceAuthPath, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device auth start failed: %d %s", resp.StatusCode, string(b))
	}

	var out DeviceAuthStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PollDeviceToken polls for token after user completes login in browser.
func (c *Client) PollDeviceToken(deviceCode string) (*DeviceTokenResponse, error) {
	payload := map[string]string{"deviceCode": deviceCode}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+deviceTokenPath, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device token poll failed: %d %s", resp.StatusCode, string(b))
	}

	var out DeviceTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Refresh exchanges refresh token for new access and refresh tokens.
func (c *Client) Refresh(refreshToken string) (*RefreshResponse, error) {
	payload := map[string]string{"refreshToken": refreshToken}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, c.baseURL+refreshPath, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh failed: %d %s", resp.StatusCode, string(b))
	}

	var out RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnsureFreshToken returns a valid access token, refreshing if needed.
func EnsureFreshToken(secrets *store.Secrets, gatewayURL string) (string, error) {
	if secrets.AccessToken == "" {
		return "", fmt.Errorf("not signed in: run 'airlock-cli sign-in' first")
	}
	if secrets.RefreshToken == "" {
		return "", fmt.Errorf("no refresh token: run 'airlock-cli sign-in' again")
	}

	exp, err := jwtExp(secrets.AccessToken)
	if err != nil {
		// Try refresh on malformed JWT
		return doRefresh(secrets, gatewayURL)
	}
	if time.Until(exp) > refreshThreshold {
		return secrets.AccessToken, nil
	}
	return doRefresh(secrets, gatewayURL)
}

func doRefresh(secrets *store.Secrets, gatewayURL string) (string, error) {
	client := NewClient(gatewayURL)
	out, err := client.Refresh(secrets.RefreshToken)
	if err != nil {
		return "", err
	}
	secrets.AccessToken = out.AccessToken
	secrets.RefreshToken = out.RefreshToken
	if err := store.SaveSecrets(secrets); err != nil {
		return "", err
	}
	return secrets.AccessToken, nil
}

// jwtExp parses JWT and returns exp time (seconds since epoch).
func jwtExp(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT format")
	}
	// Decode payload (second part) - base64url
	payload := parts[1]
	payload = strings.ReplaceAll(payload, "-", "+")
	payload = strings.ReplaceAll(payload, "_", "/")
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	dec := base64Decode(payload)
	if dec == nil {
		return time.Time{}, fmt.Errorf("invalid base64")
	}
	var m struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(dec, &m); err != nil {
		return time.Time{}, err
	}
	if m.Exp == 0 {
		return time.Time{}, fmt.Errorf("no exp claim")
	}
	return time.Unix(int64(m.Exp), 0), nil
}

func base64Decode(s string) []byte {
	// base64url without padding
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

// OpenBrowser opens the URL in the default browser (cross-platform).
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return run("cmd", "/c", "start", "", url)
	case "darwin":
		return run("open", url)
	default:
		return run("xdg-open", url)
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}