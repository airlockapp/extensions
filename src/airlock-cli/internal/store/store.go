package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	serviceName = "airlock-cli"
	configDir   = "airlock"
	configFile  = "config.json"
	secretsFile = "secrets.json" // fallback if keyring unavailable
)

// Config holds non-sensitive CLI configuration.
type Config struct {
	GatewayURL string `json:"gateway_url,omitempty"`
	EnforcerID string `json:"enforcer_id,omitempty"`
}

// Secrets holds sensitive data (tokens, keys). Stored in keyring or file.
type Secrets struct {
	AccessToken  string            `json:"access_token,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	RoutingToken string            `json:"routing_token,omitempty"`
	EncryptionKey string           `json:"encryption_key,omitempty"` // base64url
	PairedKeys   map[string]string `json:"paired_keys,omitempty"`   // signerKeyId -> Ed25519 public key base64
	X25519Priv   string            `json:"x25519_priv,omitempty"`   // base64url for pairing
}

func configDirPath() (string, error) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			base = filepath.Join(os.Getenv("USERPROFILE"), "Application Data")
		}
	default:
		base = os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = filepath.Join(os.Getenv("HOME"), ".config")
		}
	}
	dir := filepath.Join(base, configDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func secretsPath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, secretsFile), nil
}

// LoadConfig loads config from disk.
func LoadConfig() (*Config, error) {
	dir, err := configDirPath()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, configFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// SaveConfig writes config to disk.
func SaveConfig(c *Config) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, configFile), data, 0600)
}

// LoadSecrets loads secrets from file (fallback when keyring not used).
func LoadSecrets() (*Secrets, error) {
	path, err := secretsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Secrets{}, nil
		}
		return nil, err
	}
	var s Secrets
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SaveSecrets writes secrets to file.
func SaveSecrets(s *Secrets) error {
	path, err := secretsPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// ClearSecrets removes secrets file (sign-out / clear pairing).
func ClearSecrets() error {
	path, err := secretsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ConfigDir returns the config directory path for display.
func ConfigDir() (string, error) {
	return configDirPath()
}

// NormalizeGatewayURL ensures URL has no trailing slash for consistent use.
func NormalizeGatewayURL(url string) string {
	return strings.TrimSuffix(strings.TrimSpace(url), "/")
}

// ServiceName returns the keyring service name.
func ServiceName() string {
	return serviceName
}