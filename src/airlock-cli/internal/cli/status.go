package cli

import (
	"fmt"
	"os"

	"github.com/airlock/airlock-cli/internal/store"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show sign-in and pairing status",
	RunE:  runStatus,
}

func runStatus(_ *cobra.Command, _ []string) error {
	cfg, err := store.LoadConfig()
	if err != nil {
		return err
	}
	secrets, err := store.LoadSecrets()
	if err != nil {
		return err
	}

	dir, _ := store.ConfigDir()
	fmt.Fprintf(os.Stderr, "Config dir: %s\n", dir)
	fmt.Fprintf(os.Stderr, "Gateway URL: %s\n", cfg.GatewayURL)
	fmt.Fprintf(os.Stderr, "Enforcer ID: %s\n", cfg.EnforcerID)
	fmt.Fprintf(os.Stderr, "Signed in: %v\n", secrets.AccessToken != "")
	fmt.Fprintf(os.Stderr, "Paired: %v\n", secrets.RoutingToken != "" && secrets.EncryptionKey != "")
	return nil
}
