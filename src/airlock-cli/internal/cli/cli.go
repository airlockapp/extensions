package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	gatewayURL string
	diagnostic bool
)

// exitWith prints the exit code to stderr when diagnostic mode is on, then exits.
func exitWith(code int) {
	if diagnostic {
		fmt.Fprintf(os.Stderr, "airlock-cli exit code: %d\n", code)
	}
	os.Exit(code)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitWith(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "airlock-cli",
	Short: "Airlock CLI enforcer — sign in, pair, and gate commands via the Airlock gateway",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&gatewayURL, "gateway", "", "Gateway URL (default from config or env AIRLOCK_GATEWAY_URL)")
	rootCmd.PersistentFlags().BoolVar(&diagnostic, "diagnostic", false, "Enable diagnostic output (e.g. print exit code before exit, extra debug info)")
	rootCmd.AddCommand(signInCmd, signOutCmd, approveCmd, pairCmd, statusCmd)
}

// requestID generates a unique request ID (req-<16 bytes hex>).
func requestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "req-" + hex.EncodeToString(b), nil
}
