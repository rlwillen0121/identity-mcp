//go:build unix

package authz

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

const approvalSigningDomain = "MCP-AUTHZ-APPROVAL-V1\x00"

var (
	jtiHexRegex      = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	ledgerIDHexRegex = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// IntentPayloadV1 is the canonical preimage bound by a step-up approval token.
type IntentPayloadV1 struct {
	Version              string         `json:"ver"`
	GatewayID            string         `json:"gateway_id"`
	LedgerID             string         `json:"ledger_id"`
	ServerName           string         `json:"server_name"`
	ToolName             string         `json:"tool_name"`
	ActionClass          string         `json:"action_class"`
	ToolSHA256           string         `json:"tool_sha256"`
	UpstreamBinarySHA256 string         `json:"upstream_binary_sha256"`
	PolicySHA256         string         `json:"policy_sha256"`
	PrincipalIdentityID  string         `json:"principal_identity_id"`
	PrincipalSub         string         `json:"principal_sub"`
	PrincipalEmail       string         `json:"principal_email"`
	PrincipalTokenDigest string         `json:"principal_token_digest"`
	EffectiveScopes      []string       `json:"effective_scopes"`
	CleanArguments       map[string]any `json:"clean_arguments"`
}

// ApprovalTokenClaimsV1 represents the signed claims inside an mcp_appr_v1 token.
type ApprovalTokenClaimsV1 struct {
	Version      string `json:"ver"`
	JTI          string `json:"jti"`
	GatewayID    string `json:"gateway_id"`
	LedgerID     string `json:"ledger_id"`
	IntentDigest string `json:"intent_digest"`
	ApproverSub  string `json:"approver_sub"`
	TicketID     string `json:"ticket_id"`
	Interactive  bool   `json:"interactive"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

// StepUpChallengeReceiptV1 is the challenge receipt returned when a write:high-risk tool is called without a token.
type StepUpChallengeReceiptV1 struct {
	Status        string          `json:"status"`
	Stage         int             `json:"stage"`
	ErrorCode     ErrorCode       `json:"error_code"`
	ChallengeID   string          `json:"challenge_id"`
	IntentDigest  string          `json:"intent_digest"`
	IntentPayload IntentPayloadV1 `json:"intent_payload"`
	CLIHint       string          `json:"cli_hint"`
}

// BuildIntentPayload constructs IntentPayloadV1 and computes its lowercase hex SHA-256 JCS digest.
func BuildIntentPayload(
	pol *PolicyV1,
	lockfile *ManifestLockfileV1,
	ledgerID string,
	toolName string,
	tp *ToolPolicy,
	pctx *PrincipalContext,
	cleanArgs map[string]any,
) (IntentPayloadV1, string, error) {
	effScopes := make([]string, 0, len(pctx.EffectiveScope))
	for s := range pctx.EffectiveScope {
		effScopes = append(effScopes, s)
	}
	slices.Sort(effScopes)

	pinnedTool := lockfile.Tools[toolName]
	var toolSHA string
	if pinnedTool != nil {
		toolSHA = pinnedTool.ToolSHA256
	}

	intent := IntentPayloadV1{
		Version:              "mcp-authz-intent/v1",
		GatewayID:            pol.GatewayID,
		LedgerID:             ledgerID,
		ServerName:           pol.ServerName,
		ToolName:             toolName,
		ActionClass:          tp.ActionClass,
		ToolSHA256:           toolSHA,
		UpstreamBinarySHA256: lockfile.UpstreamBinarySHA256,
		PolicySHA256:         pol.PolicySHA256,
		PrincipalIdentityID:  pctx.IdentityID,
		PrincipalSub:         pctx.Sub,
		PrincipalEmail:       pctx.Email,
		PrincipalTokenDigest: pctx.TokenDigest,
		EffectiveScopes:      effScopes,
		CleanArguments:       cleanArgs,
	}

	jcsBytes, err := MarshalJCS(intent)
	if err != nil {
		return IntentPayloadV1{}, "", err
	}
	sum := sha256.Sum256(jcsBytes)
	return intent, hex.EncodeToString(sum[:]), nil
}

// WriteChallengeReceipt creates a StepUpChallengeReceiptV1 and persists it to policy.TCB.ChallengeDir.
func WriteChallengeReceipt(pol *PolicyV1, intent IntentPayloadV1, intentDigest string) (*StepUpChallengeReceiptV1, string, error) {
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return nil, "", err
	}
	challengeID := hex.EncodeToString(randBytes[:])

	challengeFilePath := filepath.Join(pol.TCB.ChallengeDir, "challenge-"+challengeID+".json")
	receipt := &StepUpChallengeReceiptV1{
		Status:        "STEP_UP_REQUIRED",
		Stage:         4,
		ErrorCode:     ErrStepUpApprovalRequired,
		ChallengeID:   challengeID,
		IntentDigest:  intentDigest,
		IntentPayload: intent,
		CLIHint: fmt.Sprintf(
			"mcp-authz-gateway approve --policy %s --intent-file %s --approver-sub <approver-email> --signing-key-file <path> --ttl 180s --ticket <INC|REQ|CHG-XXXX>",
			"<policy-path>", challengeFilePath,
		),
	}

	if pol.TCB.ChallengeDir != "" {
		if err := VerifyDirectoryTCB(pol.TCB.ChallengeDir, AllowedServiceUIDs(pol), 0o077); err != nil {
			return nil, "", err
		}
		pruneChallengeDir(pol.TCB.ChallengeDir)
		jcsReceipt, err := MarshalJCS(receipt)
		if err != nil {
			return nil, "", err
		}
		f, _, err := OpenVerifiedFile(
			challengeFilePath,
			syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY,
			0o600,
			AllowedServiceUIDs(pol),
			0o177,
		)
		if err != nil {
			return nil, "", err
		}
		_, writeErr := f.Write(append(jcsReceipt, '\n'))
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return nil, "", NewError(ErrStateLedgerUnavailable, 4, "failed to write challenge file")
		}
	}
	return receipt, challengeFilePath, nil
}

func pruneChallengeDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-15 * time.Minute)
	type fileEntry struct {
		name    string
		modTime time.Time
	}
	var kept []fileEntry
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "challenge-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
			continue
		}
		kept = append(kept, fileEntry{name: e.Name(), modTime: info.ModTime()})
	}
	if len(kept) >= 256 {
		slices.SortFunc(kept, func(a, b fileEntry) int {
			return a.modTime.Compare(b.modTime)
		})
		for i := 0; i <= len(kept)-256; i++ {
			_ = os.Remove(filepath.Join(dir, kept[i].name))
		}
	}
}

// VerifyApprovalToken validates an mcp_appr_v1 token against per-approver Ed25519 keys,
// temporal bounds, intent_digest, ledger_id, and cross-namespace Maker-Checker rules.
func VerifyApprovalToken(
	tokenStr string,
	pol *PolicyV1,
	ledgerID string,
	expectedIntentDigest string,
	pctx *PrincipalContext,
	now time.Time,
) (*ApprovalTokenClaimsV1, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, NewError(ErrStepUpApprovalRequired, 4, "step-up approval token is required")
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] != "mcp_appr_v1" || parts[1] == "" || parts[2] == "" {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "malformed step-up approval token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "invalid base64url approval payload")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "invalid base64url Ed25519 signature")
	}

	strictObj, err := DecodeStrictJSONObject(payloadBytes, true)
	if err != nil {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "approval payload failed strict JSON decode: %v", err)
	}
	jcsPayload, err := MarshalJCS(strictObj)
	if err != nil || !bytes.Equal(payloadBytes, jcsPayload) {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "approval payload is not RFC 8785 JCS canonical")
	}

	dec := json.NewDecoder(bytes.NewReader(payloadBytes))
	dec.DisallowUnknownFields()
	var claims ApprovalTokenClaimsV1
	if err := dec.Decode(&claims); err != nil {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "decode ApprovalTokenClaimsV1: %v", err)
	}

	if claims.Version != "mcp-authz-approval/v1" {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "unsupported approval token version %q", claims.Version)
	}
	if !jtiHexRegex.MatchString(claims.JTI) {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "approval token jti must be 32..64 lowercase hex characters")
	}

	// Lookup approver in policy.step_up.approvers and verify Ed25519 signature first
	appCfg, normApproverSub, found := lookupApproverConfig(pol, claims.ApproverSub)
	if !found {
		return nil, NewError(ErrApproverNotAuthorized, 4, "approver_sub %q is not registered in policy.step_up.approvers", claims.ApproverSub)
	}
	claims.ApproverSub = normApproverSub

	pubKey, err := ParseEd25519PubKeySpec(appCfg.PubKey)
	if err != nil {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "invalid approver public key: %v", err)
	}
	msg := append([]byte(approvalSigningDomain), payloadBytes...)
	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "Ed25519 signature verification failed for approver %q", claims.ApproverSub)
	}

	if claims.GatewayID != pol.GatewayID {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "approval token gateway_id %q != %q", claims.GatewayID, pol.GatewayID)
	}
	if claims.LedgerID != ledgerID {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "approval token ledger_id %q != active ledger_id %q", claims.LedgerID, ledgerID)
	}
	if pol.CompiledTicketRegex != nil && !pol.CompiledTicketRegex.MatchString(claims.TicketID) {
		return nil, NewError(ErrApprovalSignatureInvalid, 4, "approval token ticket_id %q does not match ticket_regex", claims.TicketID)
	}

	if pol.StepUp.RequireInteractiveTTY && !claims.Interactive {
		return nil, NewError(ErrApprovalNonInteractiveForbidden, 4, "policy requires interactive TTY approval (claims.interactive is false)")
	}

	// Temporal bounds
	nowUnix := now.Unix()
	skew := pol.PrincipalAuth.MaxClockSkewSeconds
	if skew <= 0 {
		skew = 30
	}
	maxTTL := pol.StepUp.MaxApprovalTTLSeconds
	if maxTTL <= 0 {
		maxTTL = 300
	}
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || (claims.ExpiresAt-claims.IssuedAt) > maxTTL {
		return nil, NewError(ErrApprovalTokenExpired, 4, "approval token TTL (%d s) invalid or exceeds max_approval_ttl_seconds (%d s)", claims.ExpiresAt-claims.IssuedAt, maxTTL)
	}
	if nowUnix < claims.IssuedAt-skew || nowUnix > claims.ExpiresAt+skew {
		return nil, NewError(ErrApprovalTokenExpired, 4, "approval token expired or not yet valid (iat=%d, exp=%d, now=%d)", claims.IssuedAt, claims.ExpiresAt, nowUnix)
	}

	// Intent digest match
	if claims.IntentDigest != expectedIntentDigest {
		return nil, NewError(ErrApprovalIntentMismatch, 4, "approval token intent_digest %q != call intent_digest %q", claims.IntentDigest, expectedIntentDigest)
	}

	// Cross-namespace Maker-Checker enforcement (including any secondary email/upn/preferred_username claims)
	if err := VerifyMakerChecker(claims.ApproverSub, appCfg, pctx.IdentityID, pctx.Sub, pctx.Email); err != nil {
		return nil, err
	}
	if pctx != nil && pctx.Claims != nil {
		for _, k := range []string{"email", "upn", "preferred_username"} {
			if s, ok := pctx.Claims[k].(string); ok && strings.TrimSpace(s) != "" {
				if err := VerifyMakerChecker(claims.ApproverSub, appCfg, pctx.IdentityID, pctx.Sub, s); err != nil {
					return nil, err
				}
			}
		}
	}

	return &claims, nil
}

func lookupApproverConfig(pol *PolicyV1, rawApproverSub string) (*ApproverConfig, string, bool) {
	if strings.TrimSpace(rawApproverSub) == "" {
		return nil, "", false
	}
	if cfg, ok := pol.StepUp.Approvers[rawApproverSub]; ok && cfg != nil {
		return cfg, rawApproverSub, true
	}
	lowerSub := asciiLower(strings.TrimSpace(rawApproverSub))
	for k, cfg := range pol.StepUp.Approvers {
		if cfg != nil && asciiLower(k) == lowerSub {
			return cfg, k, true
		}
	}
	return nil, "", false
}

// VerifyMakerChecker enforces that the approver is distinct from the requesting principal
// across all identity namespaces (PrincipalIdentityID, PrincipalSub, PrincipalEmail, approver.PrincipalIDs, approver.Emails).
func VerifyMakerChecker(approverSub string, appCfg *ApproverConfig, principalIdentityID, principalSub, principalEmail string) error {
	appSubLower := asciiLower(strings.TrimSpace(approverSub))
	pIDLower := asciiLower(strings.TrimSpace(principalIdentityID))
	pSubLower := asciiLower(strings.TrimSpace(principalSub))
	pEmailLower := asciiLower(strings.TrimSpace(principalEmail))

	matchesPrincipal := func(candidate string) bool {
		if candidate == "" {
			return false
		}
		return (pIDLower != "" && candidate == pIDLower) ||
			(pSubLower != "" && candidate == pSubLower) ||
			(pEmailLower != "" && candidate == pEmailLower)
	}

	if matchesPrincipal(appSubLower) {
		return NewError(ErrSelfApprovalForbidden, 4, "approver %q matches requesting principal", approverSub)
	}
	for _, pid := range appCfg.PrincipalIDs {
		pidLower := asciiLower(strings.TrimSpace(pid))
		if matchesPrincipal(pidLower) {
			return NewError(ErrSelfApprovalForbidden, 4, "approver principal_id %q matches requesting principal", pid)
		}
	}
	for _, em := range appCfg.Emails {
		emLower := asciiLower(strings.TrimSpace(em))
		if matchesPrincipal(emLower) {
			return NewError(ErrSelfApprovalForbidden, 4, "approver email %q matches requesting principal", em)
		}
	}
	return nil
}

// ApproveOptions holds CLI parameters for `mcp-authz-gateway approve`.
type ApproveOptions struct {
	PolicyPath     string
	IntentFilePath string
	ApproverSub    string
	SigningKeyPath string
	TTL            time.Duration
	TicketID       string
	Yes            bool
	TTYReader      io.Reader // optional override for testing interactive prompt
	StderrWriter   io.Writer
	Now            time.Time
}

// SignApprovalFromCLI implements the `mcp-authz-gateway approve` workflow (§3.4), including full
// IntentPayloadV1 preimage recomputation against policy.json and lockfile_path.
func SignApprovalFromCLI(opts ApproveOptions) (string, error) {
	if opts.StderrWriter == nil {
		opts.StderrWriter = os.Stderr
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}

	pol, err := LoadAndValidatePolicy(opts.PolicyPath)
	if err != nil {
		return "", err
	}
	lockfile, rawLockBytes, err := LoadLockfile(pol.TCB.LockfilePath, AllowedConfigUIDs(pol))
	if err != nil {
		return "", err
	}
	if err := VerifyPolicyAndLockfileSignature(pol, pol.RawPolicyBytes, rawLockBytes); err != nil {
		return "", err
	}

	rawIntentFile, err := ReadVerifiedFile(opts.IntentFilePath, []uint32{0, uint32(os.Geteuid())}, 0o022, MaxToolArgumentsBytes*2)
	if err != nil {
		return "", err
	}
	if _, err := DecodeStrictJSONWithCap(rawIntentFile, MaxToolArgumentsBytes*2, true); err != nil {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent file failed strict JSON decode: %v", err)
	}

	var challenge StepUpChallengeReceiptV1
	dec := json.NewDecoder(bytes.NewReader(rawIntentFile))
	dec.UseNumber()
	if err := dec.Decode(&challenge); err != nil {
		return "", NewError(ErrIntentPreimageMismatch, 0, "decode challenge receipt: %v", err)
	}
	intent := challenge.IntentPayload
	if intent.Version != "mcp-authz-intent/v1" {
		return "", NewError(ErrIntentPreimageMismatch, 0, "unsupported intent payload version %q", intent.Version)
	}
	if intent.GatewayID != pol.GatewayID {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent gateway_id %q != policy gateway_id %q", intent.GatewayID, pol.GatewayID)
	}
	if intent.ServerName != pol.ServerName {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent server_name %q != policy server_name %q", intent.ServerName, pol.ServerName)
	}
	if !ledgerIDHexRegex.MatchString(intent.LedgerID) {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent ledger_id %q is malformed", intent.LedgerID)
	}
	if intent.PolicySHA256 != pol.PolicySHA256 {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent policy_sha256 %q != local policy_sha256 %q", intent.PolicySHA256, pol.PolicySHA256)
	}
	if intent.UpstreamBinarySHA256 != lockfile.UpstreamBinarySHA256 {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent upstream_binary_sha256 %q != lockfile %q", intent.UpstreamBinarySHA256, lockfile.UpstreamBinarySHA256)
	}
	tp, hasTP := pol.Tools[intent.ToolName]
	if !hasTP || tp == nil || !tp.Enabled || intent.ActionClass != tp.ActionClass {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent tool %q (action_class=%q) is not enabled with matching action_class in policy.json", intent.ToolName, intent.ActionClass)
	}
	pinnedTool, ok := lockfile.Tools[intent.ToolName]
	if !ok || pinnedTool == nil || intent.ToolSHA256 != pinnedTool.ToolSHA256 {
		return "", NewError(ErrIntentPreimageMismatch, 0, "intent tool_sha256 for %q does not match lockfile", intent.ToolName)
	}

	// Recompute JCS(intent_payload) and verify SHA-256 equals challenge.IntentDigest!
	intentJCS, err := MarshalJCS(intent)
	if err != nil {
		return "", NewError(ErrIntentPreimageMismatch, 0, "JCS serialize intent_payload: %v", err)
	}
	recomputedSum := sha256.Sum256(intentJCS)
	recomputedHex := hex.EncodeToString(recomputedSum[:])
	if recomputedHex != challenge.IntentDigest {
		return "", NewError(ErrIntentPreimageMismatch, 0, "recomputed intent digest %s != challenge intent_digest %s", recomputedHex, challenge.IntentDigest)
	}

	// Verify approver & signing key
	appCfg, normApproverSub, found := lookupApproverConfig(pol, opts.ApproverSub)
	if !found {
		return "", NewError(ErrApproverNotAuthorized, 4, "approver %q not in policy.step_up.approvers", opts.ApproverSub)
	}
	if err := VerifyMakerChecker(normApproverSub, appCfg, intent.PrincipalIdentityID, intent.PrincipalSub, intent.PrincipalEmail); err != nil {
		return "", err
	}

	keyBytes, err := ReadVerifiedFile(opts.SigningKeyPath, []uint32{uint32(os.Geteuid())}, 0o177, 4096)
	if err != nil {
		return "", err
	}
	privKey, err := ParseEd25519PrivKeySpec(string(keyBytes))
	if err != nil {
		return "", err
	}
	expectedPub, err := ParseEd25519PubKeySpec(appCfg.PubKey)
	if err != nil {
		return "", err
	}
	derivedPub := privKey.Public().(ed25519.PublicKey)
	if !slices.Equal(derivedPub, expectedPub) {
		return "", NewError(ErrApprovalSignatureInvalid, 4, "signing key does not match public key registered for %q", normApproverSub)
	}

	if pol.CompiledTicketRegex != nil && !pol.CompiledTicketRegex.MatchString(opts.TicketID) {
		return "", NewError(ErrApprovalSignatureInvalid, 4, "ticket %q does not match step_up.ticket_regex", opts.TicketID)
	}
	ttlSec := int64(opts.TTL.Seconds())
	maxTTL := pol.StepUp.MaxApprovalTTLSeconds
	if maxTTL <= 0 {
		maxTTL = 300
	}
	if ttlSec <= 0 || ttlSec > maxTTL {
		return "", NewError(ErrApprovalTokenExpired, 4, "requested TTL %ds must be in [1, %d]", ttlSec, maxTTL)
	}

	// Render intent summary using FormatSafeTerminalASCII to stderr
	argsJCS, _ := MarshalJCS(intent.CleanArguments)
	fmt.Fprintf(opts.StderrWriter, "=== STEP-UP APPROVAL REVIEW ===\n")
	fmt.Fprintf(opts.StderrWriter, "Gateway ID:   %s\n", FormatSafeTerminalASCII(intent.GatewayID))
	fmt.Fprintf(opts.StderrWriter, "Ledger ID:    %s\n", FormatSafeTerminalASCII(intent.LedgerID))
	fmt.Fprintf(opts.StderrWriter, "Server / Tool:%s / %s (%s)\n", FormatSafeTerminalASCII(intent.ServerName), FormatSafeTerminalASCII(intent.ToolName), FormatSafeTerminalASCII(intent.ActionClass))
	fmt.Fprintf(opts.StderrWriter, "Principal:    id=%s sub=%s email=%s\n", FormatSafeTerminalASCII(intent.PrincipalIdentityID), FormatSafeTerminalASCII(intent.PrincipalSub), FormatSafeTerminalASCII(intent.PrincipalEmail))
	fmt.Fprintf(opts.StderrWriter, "Arguments:    %s\n", FormatSafeTerminalASCII(string(argsJCS)))
	fmt.Fprintf(opts.StderrWriter, "Intent Digest:%s\n", FormatSafeTerminalASCII(recomputedHex))

	interactive := false
	if !opts.Yes {
		var r io.Reader = opts.TTYReader
		if r == nil {
			ttyFile, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return "", NewError(ErrApprovalNonInteractiveForbidden, 4, "cannot open /dev/tty for interactive approval: %v", err)
			}
			defer ttyFile.Close()
			r = ttyFile
		}
		fmt.Fprintf(opts.StderrWriter, "Approve execution of %s on %s? [y/N]: ", FormatSafeTerminalASCII(intent.ToolName), FormatSafeTerminalASCII(intent.ServerName))
		scanner := bufio.NewScanner(r)
		if !scanner.Scan() {
			return "", NewError(ErrApprovalNonInteractiveForbidden, 4, "approval aborted (no input)")
		}
		ans := strings.TrimSpace(scanner.Text())
		if ans != "y" && ans != "Y" {
			return "", NewError(ErrStepUpApprovalRequired, 4, "step-up approval declined by operator")
		}
		interactive = true
	} else if pol.StepUp.RequireInteractiveTTY {
		return "", NewError(ErrApprovalNonInteractiveForbidden, 4, "--yes is forbidden when step_up.require_interactive_tty is true")
	}

	var jtiRand [16]byte
	if _, err := rand.Read(jtiRand[:]); err != nil {
		return "", err
	}
	iat := opts.Now.Unix()
	claims := ApprovalTokenClaimsV1{
		Version:      "mcp-authz-approval/v1",
		JTI:          hex.EncodeToString(jtiRand[:]),
		GatewayID:    pol.GatewayID,
		LedgerID:     intent.LedgerID,
		IntentDigest: recomputedHex,
		ApproverSub:  normApproverSub,
		TicketID:     opts.TicketID,
		Interactive:  interactive,
		IssuedAt:     iat,
		ExpiresAt:    iat + ttlSec,
	}

	payloadJCS, err := MarshalJCS(claims)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(privKey, append([]byte(approvalSigningDomain), payloadJCS...))
	tok := "mcp_appr_v1." + base64.RawURLEncoding.EncodeToString(payloadJCS) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return tok, nil
}
