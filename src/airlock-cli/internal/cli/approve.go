package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/airlock/airlock-cli/internal/artifact"
	"github.com/airlock/airlock-cli/internal/auth"
	"github.com/airlock/airlock-cli/internal/gateway"
	"github.com/airlock/airlock-cli/internal/store"
	"github.com/airlock/airlock-cli/internal/verify"
	"github.com/spf13/cobra"
)

var (
	approveShell    string
	approveCwd     string
	approveCommand string
	approveSessionID string
	approveShellPid string
	approveHost    string
	approveTimeout int
)

var approveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Request approval for a command from the Airlock gateway; exit 0 if approved, non-zero if denied/timeout",
	RunE:  runApprove,
}

func init() {
	approveCmd.Flags().StringVar(&approveShell, "shell", "", "Shell name (e.g. zsh)")
	approveCmd.Flags().StringVar(&approveCwd, "cwd", "", "Current working directory")
	approveCmd.Flags().StringVar(&approveCommand, "command", "", "Command to approve (required)")
	approveCmd.Flags().StringVar(&approveSessionID, "session-id", "", "Session ID")
	approveCmd.Flags().StringVar(&approveShellPid, "shell-pid", "", "Shell PID")
	approveCmd.Flags().StringVar(&approveHost, "host", "", "Host name")
	approveCmd.Flags().IntVar(&approveTimeout, "timeout", 300, "Max seconds to wait for approval (default 300)")
	_ = approveCmd.MarkFlagRequired("command")
}

func runApprove(cmd *cobra.Command, _ []string) error {
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
		return fmt.Errorf("gateway URL not set: run 'airlock-cli sign-in' or set --gateway / AIRLOCK_GATEWAY_URL")
	}

	token, err := auth.EnsureFreshToken(secrets, url)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	if secrets.EncryptionKey == "" || secrets.RoutingToken == "" {
		return fmt.Errorf("not paired: run 'airlock-cli pair' and complete pairing on your mobile device")
	}

	keyBytes, err := base64.RawURLEncoding.DecodeString(secrets.EncryptionKey)
	if err != nil {
		return fmt.Errorf("invalid encryption key: %w", err)
	}

	enforcerID := cfg.EnforcerID
	if enforcerID == "" {
		enforcerID = "airlock-cli"
	}

	requestID, err := requestID()
	if err != nil {
		return err
	}
	if diagnostic {
		fmt.Fprintf(os.Stderr, "[diagnostic] gateway=%s timeout=%ds requestId=%s\n", url, approveTimeout, requestID)
	}

	workspaceName := approveCwd
	if workspaceName == "" {
		workspaceName = "cli"
	}

	payload := &artifact.ApprovePayload{
		ActionType:  "command-approval",
		CommandText: approveCommand,
		ButtonText:  "Approve",
		Workspace:   workspaceName,
		RepoName:    "",
		Source:      "airlock-cli",
		Shell:       approveShell,
		Cwd:         approveCwd,
		SessionID:   approveSessionID,
		ShellPid:    approveShellPid,
		Host:        approveHost,
	}

	env, expectedHash, err := artifact.BuildEnvelope(requestID, enforcerID, payload, keyBytes, secrets.RoutingToken, workspaceName)
	if err != nil {
		return err
	}

	gw := gateway.NewClient(url, token)
	if err := gw.SubmitArtifact(env); err != nil {
		return fmt.Errorf("submit artifact: %w", err)
	}
	if diagnostic {
		fmt.Fprintln(os.Stderr, "[diagnostic] artifact submitted, polling for decision")
	}

	deadline := time.Now().Add(time.Duration(approveTimeout) * time.Second)
	pollSec := 25
	if pollSec > approveTimeout {
		pollSec = approveTimeout
	}
	if pollSec < 1 {
		pollSec = 1
	}

	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining < time.Duration(pollSec)*time.Second {
			pollSec = int(remaining.Seconds())
			if pollSec < 1 {
				pollSec = 1
			}
		}
		body, err := gw.WaitForDecision(requestID, pollSec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Poll error:", err)
			time.Sleep(time.Second)
			continue
		}
		if body == nil {
			continue
		}

		outcome := verify.VerifyDecision(body, expectedHash, secrets.PairedKeys)
		if outcome.Error != "" {
			fmt.Fprintln(os.Stderr, "Verification failed:", outcome.Error)
			exitWith(2)
		}
		if outcome.Approved {
			if outcome.Reason != "" {
				fmt.Fprintln(os.Stderr, "Approved:", outcome.Reason)
			}
			exitWith(0)
		}
		fmt.Fprintln(os.Stderr, "Denied:", outcome.Reason)
		exitWith(1)
	}

	fmt.Fprintln(os.Stderr, "Approval timeout — no decision received")
	exitWith(3)
	return nil // unreachable
}

func resolveGatewayURL(cfg *store.Config) string {
	if gatewayURL != "" {
		return store.NormalizeGatewayURL(gatewayURL)
	}
	if cfg != nil && cfg.GatewayURL != "" {
		return store.NormalizeGatewayURL(cfg.GatewayURL)
	}
	return store.NormalizeGatewayURL(os.Getenv("AIRLOCK_GATEWAY_URL"))
}
