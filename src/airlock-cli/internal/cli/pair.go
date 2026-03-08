package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/airlock/airlock-cli/internal/auth"
	"github.com/airlock/airlock-cli/internal/crypto"
	"github.com/airlock/airlock-cli/internal/pairing"
	"github.com/airlock/airlock-cli/internal/store"
	"github.com/spf13/cobra"
)

var (
	pairWorkspace string
	pairLabel    string
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Pair this CLI with your mobile approver (shows code to enter in the app)",
	RunE:  runPair,
}

func init() {
	pairCmd.Flags().StringVar(&pairWorkspace, "workspace", "cli", "Workspace name shown in the mobile app")
	pairCmd.Flags().StringVar(&pairLabel, "label", "Airlock CLI", "Enforcer label shown in the mobile app")
}

func runPair(cmd *cobra.Command, _ []string) error {
	cfg, err := store.LoadConfig()
	if err != nil {
		return err
	}
	secrets, err := store.LoadSecrets()
	if err != nil {
		return err
	}
	url := resolveGatewayURL(cfg)
	if url == "" {
		return fmt.Errorf("gateway URL not set: run 'airlock-cli sign-in' first")
	}

	token, err := auth.EnsureFreshToken(secrets, url)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	kp, err := crypto.GenerateX25519Keypair()
	if err != nil {
		return err
	}

	deviceID := "airlock-cli-" + base64.RawURLEncoding.EncodeToString(kp.PublicKey)[:8]
	enforcerID := cfg.EnforcerID
	if enforcerID == "" {
		enforcerID = "airlock-cli"
	}

	x25519PubB64 := crypto.PublicKeyToBase64URL(kp.PublicKey)
	resp, err := pairing.Initiate(url, token, deviceID, enforcerID, pairLabel, pairWorkspace, x25519PubB64)
	if err != nil {
		return fmt.Errorf("initiate pairing: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Pairing code: %s\n", resp.PairingCode)
	fmt.Fprintf(os.Stderr, "Enter this code in the Airlock mobile app. Waiting for completion...\n")

	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		status, err := pairing.Status(url, token, resp.PairingNonce)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Status poll:", err)
			continue
		}
		if status.State != "Completed" {
			continue
		}

		encKeyB64, pairedKeys, err := pairing.CompletePairing(status.ResponseJSON, status.RoutingToken, kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("complete pairing: %w", err)
		}

		secrets.RoutingToken = status.RoutingToken
		secrets.EncryptionKey = encKeyB64
		secrets.PairedKeys = pairedKeys
		if err := store.SaveSecrets(secrets); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Pairing complete. You can now use 'airlock-cli approve'.")
		return nil
	}
	return fmt.Errorf("pairing timed out")
}
