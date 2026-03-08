package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to the Airlock Gateway (artifacts, wait).
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates a gateway client with optional Bearer token.
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

// SubmitArtifact POSTs artifact.submit envelope. Returns nil on success.
func (c *Client) SubmitArtifact(envelope interface{}) error {
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/v1/artifacts", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("submit request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit failed: %d %s", resp.StatusCode, string(b))
	}
	return nil
}

// WaitForDecision long-polls GET /v1/exchanges/{requestId}/wait. Returns decision.deliver body or nil if timeout.
func (c *Client) WaitForDecision(requestID string, timeoutSec int) (map[string]interface{}, error) {
	if timeoutSec <= 0 {
		timeoutSec = 25
	}
	if timeoutSec > 60 {
		timeoutSec = 60
	}
	url := fmt.Sprintf("%s/v1/exchanges/%s/wait?timeout=%d", c.BaseURL, requestID, timeoutSec)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	// Use a client with longer timeout for long-poll
	client := &http.Client{Timeout: time.Duration(timeoutSec+10) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wait request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil // no decision yet
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("wait failed: %d %s", resp.StatusCode, string(b))
	}

	var env struct {
		MsgType string                 `json:"msgType"`
		Body    map[string]interface{} `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, err
	}
	if env.MsgType != "decision.deliver" {
		return nil, fmt.Errorf("unexpected msgType: %s", env.MsgType)
	}
	return env.Body, nil
}
