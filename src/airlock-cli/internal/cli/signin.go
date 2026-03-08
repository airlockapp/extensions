package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/airlock/airlock-cli/internal/auth"
	"github.com/airlock/airlock-cli/internal/store"
	"github.com/spf13/cobra"
)

var signInCmd = &cobra.Command{
	Use:   "sign-in",
	Short: "Sign in via device authorization (opens browser)",
	RunE:  runSignIn,
}

func runSignIn(cmd *cobra.Command, _ []string) error {
	cfg, err := store.LoadConfig()
	if err != nil {
		return err
	}
	url := gatewayURL
	if url == "" {
		url = cfg.GatewayURL
	}
	if url == "" {
		url = os.Getenv("AIRLOCK_GATEWAY_URL")
	}
	if url == "" {
		url = "https://localhost:7145"
	}
	url = store.NormalizeGatewayURL(url)

	client := auth.NewClient(url)
	start, err := client.StartDeviceAuth()
	if err != nil {
		return fmt.Errorf("start device auth: %w", err)
	}

	loginURL := start.VerificationURIComplete
	if loginURL == "" {
		loginURL = start.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "Opening browser to sign in. If it doesn't open, visit:\n  %s\n", loginURL)
	fmt.Fprintf(os.Stderr, "Code: %s\n", start.UserCode)
	if err := auth.OpenBrowser(loginURL); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open browser: %v\n", err)
	}

	interval := start.Interval
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
	pollInterval := time.Duration(interval) * time.Second

	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		resp, err := client.PollDeviceToken(start.DeviceCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Poll error: %v\n", err)
			continue
		}
		if resp.Completed {
			secrets, _ := store.LoadSecrets()
			if secrets == nil {
				secrets = &store.Secrets{}
			}
			secrets.AccessToken = resp.AccessToken
			secrets.RefreshToken = resp.RefreshToken
			if err := store.SaveSecrets(secrets); err != nil {
				return err
			}
			cfg.GatewayURL = url
			if cfg.EnforcerID == "" {
				cfg.EnforcerID = "airlock-cli"
			}
			if err := store.SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Signed in successfully.")
			return nil
		}
		if resp.Error == "authorization_pending" || resp.Error == "slow_down" {
			continue
		}
		return fmt.Errorf("login failed: %s", resp.Error)
	}
	return fmt.Errorf("login timed out")
}
