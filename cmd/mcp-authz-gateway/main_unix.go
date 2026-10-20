//go:build unix

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rlwillen0121/identity-mcp/internal/authz"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	subcmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch subcmd {
	case "serve", "run":
		err = runServe(ctx, args)
	case "init-state":
		err = runInitState(args)
	case "pin":
		err = runPin(ctx, args)
	case "approve":
		err = runApprove(args)
	case "verify-audit":
		err = runVerifyAudit(args)
	case "repair", "repair-ledger":
		err = runRepair(args)
	case "revoke-grant", "revoke":
		err = runRevokeGrant(args)
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-authz-gateway %s: %v\n", subcmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: mcp-authz-gateway <subcommand> [flags]

Subcommands:
  serve         Run the stdio MCP authorization proxy (--policy <abs-path>)
  init-state    Initialize state.db, state.db.lock, audit.jsonl, challenge_dir, and empty_home_dir
  pin           Verify upstream binary and write canonical tool manifest lockfile
  approve       Verify challenge receipt preimage and sign a step-up Ed25519 approval token
  verify-audit  Verify audit.jsonl SHA-256 hash chain against state.db audit_hwm
  repair        Truncate torn final crash line in state.db / audit.jsonl and reconcile audit_hwm
  revoke-grant  Revoke a permanent SoD grant record in state.db
`)
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return fmt.Errorf("serve accepts only --policy /abs/path/to/policy.json")
	}
	return authz.ServeStdio(ctx, *policyPath)
}

func runInitState(args []string) error {
	fs := flag.NewFlagSet("init-state", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return fmt.Errorf("init-state requires --policy /abs/path/to/policy.json")
	}
	pol, err := authz.LoadAndValidatePolicy(*policyPath)
	if err != nil {
		return err
	}
	ledgerID, err := authz.InitState(pol, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Initialized state ledger (ledger_id=%s)\n", ledgerID)
	return nil
}

func runPin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	yes := fs.Bool("yes", false, "skip /dev/tty interactive confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return fmt.Errorf("pin requires --policy /abs/path/to/policy.json [--yes]")
	}
	_, err := authz.PinUpstreamCLI(ctx, authz.PinOptions{
		PolicyPath:   *policyPath,
		Yes:          *yes,
		StderrWriter: os.Stderr,
	})
	return err
}

func runApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	intentFile := fs.String("intent-file", "", "canonical absolute path to challenge receipt JSON")
	approverSub := fs.String("approver-sub", "", "approver identity (must exist in policy.step_up.approvers)")
	signingKey := fs.String("signing-key-file", "", "canonical absolute path to Ed25519 private key file")
	ttl := fs.Duration("ttl", 180*time.Second, "approval token TTL (e.g. 180s)")
	ticket := fs.String("ticket", "", "change/incident ticket ID")
	yes := fs.Bool("yes", false, "skip /dev/tty confirmation (sets interactive:false)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" || *intentFile == "" || *approverSub == "" || *signingKey == "" || *ticket == "" {
		return fmt.Errorf("approve requires --policy, --intent-file, --approver-sub, --signing-key-file, --ttl, and --ticket")
	}
	tok, err := authz.SignApprovalFromCLI(authz.ApproveOptions{
		PolicyPath:     *policyPath,
		IntentFilePath: *intentFile,
		ApproverSub:    *approverSub,
		SigningKeyPath: *signingKey,
		TTL:            *ttl,
		TicketID:       *ticket,
		Yes:            *yes,
		StderrWriter:   os.Stderr,
		Now:            time.Now(),
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, tok)
	return nil
}

func runVerifyAudit(args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return fmt.Errorf("verify-audit requires --policy /abs/path/to/policy.json")
	}
	pol, err := authz.LoadAndValidatePolicy(*policyPath)
	if err != nil {
		return err
	}
	seq, hash, err := authz.VerifyAuditCLI(pol)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "OK (%d records verified, head=%s)\n", seq, hash)
	return nil
}

func runRepair(args []string) error {
	fs := flag.NewFlagSet("repair", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return fmt.Errorf("repair requires --policy /abs/path/to/policy.json")
	}
	pol, err := authz.LoadAndValidatePolicy(*policyPath)
	if err != nil {
		return err
	}
	return authz.RepairLedgerCLI(pol, time.Now())
}

func runRevokeGrant(args []string) error {
	fs := flag.NewFlagSet("revoke-grant", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	policyPath := fs.String("policy", "", "canonical absolute path to policy.json")
	subject := fs.String("subject", "", "canonical subject ID")
	entitlement := fs.String("entitlement", "", "canonical entitlement ID")
	operator := fs.String("operator", "", "operator sub or email")
	ticket := fs.String("ticket", "", "change/incident ticket ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" || *subject == "" || *entitlement == "" || *operator == "" || *ticket == "" {
		return fmt.Errorf("revoke-grant requires --policy, --subject, --entitlement, --operator, and --ticket")
	}
	pol, err := authz.LoadAndValidatePolicy(*policyPath)
	if err != nil {
		return err
	}
	return authz.RevokeGrantCLI(pol, *subject, *entitlement, *operator, *ticket, time.Now())
}
