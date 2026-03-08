package cli

import (
	"fmt"
	"os"

	"github.com/airlock/airlock-cli/internal/store"
	"github.com/spf13/cobra"
)

var signOutCmd = &cobra.Command{
	Use:   "sign-out",
	Short: "Sign out and clear stored tokens and pairing data",
	RunE:  runSignOut,
}

func runSignOut(_ *cobra.Command, _ []string) error {
	if err := store.ClearSecrets(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed out. Tokens and pairing data cleared.")
	return nil
}
