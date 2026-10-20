//go:build unix

package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

const ApprovalTokenArgName = "__mcp_authz_approval_token"

var (
	pathExprRegex     = regexp.MustCompile(`^[a-zA-Z0-9_]+(\[\*\])?(\.[a-zA-Z0-9_]+(\[\*\])?)*$`)
	idAlnumRegex      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`)
	emailOrUPNRegex   = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$`)
	uuidCanonicalRgx  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dnExactRegex      = regexp.MustCompile(`^[A-Za-z0-9=,._ -]{1,512}$`)
	reservedSelfNames = map[string]bool{
		"me":      true,
		"self":    true,
		"current": true,
		"default": true,
		"@me":     true,
	}
)

// PolicyV1 is the normative configuration structure for mcp-authz-gateway.
type PolicyV1 struct {
	SchemaVersion               string                        `json:"schema_version"`
	GatewayID                   string                        `json:"gateway_id"`
	ServerName                  string                        `json:"server_name"`
	PinMode                     string                        `json:"pin_mode"`
	ReverifyManifestBeforeWrite *bool                         `json:"reverify_manifest_before_write,omitempty"`
	TCB                         TCBConfig                     `json:"tcb"`
	Upstream                    UpstreamConfig                `json:"upstream"`
	PrincipalAuth               PrincipalAuthConfig           `json:"principal_auth"`
	AgentProfile                AgentProfileConfig            `json:"agent_profile"`
	ProtectedResources          map[string]*ProtectedCategory `json:"protected_resources"`
	SoDRules                    []SoDRule                     `json:"sod_rules"`
	SubjectExistingEntitlements map[string][]string           `json:"subject_existing_entitlements,omitempty"`
	StepUp                      StepUpConfig                  `json:"step_up"`
	Tools                       map[string]*ToolPolicy        `json:"tools"`

	// Compiled state populated by LoadAndValidatePolicy
	PolicySHA256          string                        `json:"-"`
	RawPolicyBytes        []byte                        `json:"-"`
	ParsedVerifierKeys    map[string]*ParsedVerifierKey `json:"-"`
	CompiledIdentityRegex *regexp.Regexp                `json:"-"`
	CompiledTicketRegex   *regexp.Regexp                `json:"-"`
}

type TCBConfig struct {
	IsolationMode        string `json:"isolation_mode"`
	ServiceUID           int    `json:"service_uid,omitempty"`
	ForbiddenUIDs        []int  `json:"forbidden_uids,omitempty"`
	AllowSameUIDInGoTest bool   `json:"allow_same_uid_in_go_test,omitempty"`
	LockfilePath         string `json:"lockfile_path"`
	StateDBPath          string `json:"state_db_path"`
	AuditLogPath         string `json:"audit_log_path"`
	ChallengeDir         string `json:"challenge_dir"`
	EmptyHomeDir         string `json:"empty_home_dir"`
	AdminPubKey          string `json:"admin_pubkey,omitempty"`
	PolicySigPath        string `json:"policy_sig_path,omitempty"`
	SSLCertFile          string `json:"ssl_cert_file,omitempty"`
	SSLCertDir           string `json:"ssl_cert_dir,omitempty"`
}

type UpstreamConfig struct {
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	EnvFile        string   `json:"env_file"`
	PassEnv        []string `json:"pass_env"`
	SecretEnvKeys  []string `json:"secret_env_keys"`
	CallTimeoutMs  int      `json:"call_timeout_ms"`
	MaxOutputBytes int      `json:"max_output_bytes"`
}

type PrincipalAuthConfig struct {
	RequireJWT              *bool                          `json:"require_jwt"`
	AnonymousScopes         []string                       `json:"anonymous_scopes,omitempty"`
	IdentityClaim           string                         `json:"identity_claim,omitempty"`
	IdentityRegex           string                         `json:"identity_regex,omitempty"`
	IdentityCaseMode        string                         `json:"identity_case_mode,omitempty"`
	AllowedAlgs             []string                       `json:"allowed_algs,omitempty"`
	Issuer                  string                         `json:"issuer,omitempty"`
	Audience                string                         `json:"audience,omitempty"`
	MaxClockSkewSeconds     int64                          `json:"max_clock_skew_seconds,omitempty"`
	MaxTokenLifetimeSeconds int64                          `json:"max_token_lifetime_seconds,omitempty"`
	AllowPerCallJWT         bool                           `json:"allow_per_call_jwt"`
	PublicKeys              map[string]string              `json:"public_keys,omitempty"`
	ScopeClaims             []string                       `json:"scope_claims,omitempty"`
	ClaimToScopeMap         map[string]map[string][]string `json:"claim_to_scope_map,omitempty"`
}

type AgentProfileConfig struct {
	AgentID                  string   `json:"agent_id"`
	AllowedScopes            []string `json:"allowed_scopes"`
	HideUnauthorizedTools    bool     `json:"hide_unauthorized_tools"`
	BudgetWindowSeconds      int64    `json:"budget_window_seconds"`
	MaxWriteCallsPerMinute   int      `json:"max_write_calls_per_minute"`
	MaxWriteTargetsPerWindow int      `json:"max_write_targets_per_window"`
	MaxChallengesPerMinute   int      `json:"max_challenges_per_minute"`
}

type ProtectedCategory struct {
	CaseInsensitive bool             `json:"case_insensitive"`
	Exact           []string         `json:"exact,omitempty"`
	Prefixes        []string         `json:"prefixes,omitempty"`
	Regexes         []string         `json:"regexes,omitempty"`
	CompiledRegexes []*regexp.Regexp `json:"-"`
}

type SoDRule struct {
	RuleID                  string   `json:"rule_id"`
	ConflictingEntitlements []string `json:"conflicting_entitlements"`
	CaseInsensitive         bool     `json:"case_insensitive"`
}

type StepUpConfig struct {
	MaxApprovalTTLSeconds int64                      `json:"max_approval_ttl_seconds"`
	RequireInteractiveTTY bool                       `json:"require_interactive_tty"`
	TicketRegex           string                     `json:"ticket_regex"`
	Approvers             map[string]*ApproverConfig `json:"approvers"`
}

type ApproverConfig struct {
	PubKey       string   `json:"pubkey"`
	PrincipalIDs []string `json:"principal_ids"`
	Emails       []string `json:"emails"`
}

type ToolPolicy struct {
	Enabled                 bool                     `json:"enabled"`
	ActionClass             string                   `json:"action_class"`
	RequiredScopes          []string                 `json:"required_scopes"`
	ForbidSelfTarget        *bool                    `json:"forbid_self_target,omitempty"`
	PrimaryTargetPath       string                   `json:"primary_target_path,omitempty"`
	SubjectTargetBindings   []SubjectTargetBinding   `json:"subject_target_bindings,omitempty"`
	ProtectedTargetBindings []ProtectedTargetBinding `json:"protected_target_bindings,omitempty"`
	SoDBinding              *SoDBinding              `json:"sod_binding,omitempty"`
	ArrayCapBindings        []ArrayCapBinding        `json:"array_cap_bindings,omitempty"`
	LimitArgBindings        []LimitArgBinding        `json:"limit_arg_bindings,omitempty"`
	ArgConstraints          *ArgConstraints          `json:"arg_constraints,omitempty"`
	RedactArgs              []string                 `json:"redact_args,omitempty"`
}

type SubjectTargetBinding struct {
	Path           string         `json:"path"`
	JWTClaims      []string       `json:"jwt_claims"`
	Normalizer     string         `json:"normalizer"`
	CanonicalRegex string         `json:"canonical_regex"`
	CaseMode       string         `json:"case_mode"`
	Optional       bool           `json:"optional"`
	CompiledRegex  *regexp.Regexp `json:"-"`
}

type ProtectedTargetBinding struct {
	Path           string         `json:"path"`
	Categories     []string       `json:"categories"`
	Normalizer     string         `json:"normalizer"`
	CanonicalRegex string         `json:"canonical_regex"`
	CaseMode       string         `json:"case_mode"`
	Optional       bool           `json:"optional"`
	CompiledRegex  *regexp.Regexp `json:"-"`
}

type SoDBinding struct {
	SubjectPath                   string         `json:"subject_path"`
	SubjectNormalizer             string         `json:"subject_normalizer"`
	SubjectCanonicalRegex         string         `json:"subject_canonical_regex"`
	SubjectCaseMode               string         `json:"subject_case_mode"`
	EntitlementPath               string         `json:"entitlement_path"`
	EntitlementNormalizer         string         `json:"entitlement_normalizer"`
	EntitlementCanonicalRegex     string         `json:"entitlement_canonical_regex"`
	EntitlementCaseMode           string         `json:"entitlement_case_mode"`
	CompiledSubjectRegex          *regexp.Regexp `json:"-"`
	CompiledEntitlementCanonRegex *regexp.Regexp `json:"-"`
}

type ArrayCapBinding struct {
	Path     string `json:"path"`
	MaxItems int    `json:"max_items"`
}

type LimitArgBinding struct {
	Path         string `json:"path"`
	DefaultValue int    `json:"default_value"`
	MaxValue     int    `json:"max_value"`
}

type NumericBound struct {
	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`
}

type ArgConstraints struct {
	RequiredNonEmpty []string                  `json:"required_non_empty,omitempty"`
	RegexMatch       map[string]string         `json:"regex_match,omitempty"`
	NumericBounds    map[string]NumericBound   `json:"numeric_bounds,omitempty"`
	EnumAllowlist    map[string][]string       `json:"enum_allowlist,omitempty"`
	OptionalPaths    []string                  `json:"optional_paths,omitempty"`
	CompiledRegexes  map[string]*regexp.Regexp `json:"-"`
}

// LoadAndValidatePolicy loads policy.json via OpenVerifiedFile and performs all startup policy checks.
func LoadAndValidatePolicy(policyPath string) (*PolicyV1, error) {
	if err := ValidateCanonicalPath(policyPath); err != nil {
		return nil, err
	}
	rawBytes, err := ReadVerifiedFile(policyPath, []uint32{0, uint32(os.Geteuid())}, 0o022, MaxConfigFileBytes)
	if err != nil {
		return nil, err
	}
	return ParseAndValidatePolicyBytes(policyPath, rawBytes)
}

// ParseAndValidatePolicyBytes parses and validates a raw policy.json payload.
func ParseAndValidatePolicyBytes(policyPath string, rawBytes []byte) (*PolicyV1, error) {
	strictVal, err := DecodeStrictJSONWithCap(rawBytes, MaxConfigFileBytes, false)
	if err != nil {
		return nil, err
	}
	jcsBytes, err := MarshalJCS(strictVal)
	if err != nil {
		return nil, err
	}
	polHash := sha256.Sum256(jcsBytes)

	dec := json.NewDecoder(bytes.NewReader(rawBytes))
	dec.DisallowUnknownFields()
	var pol PolicyV1
	if err := dec.Decode(&pol); err != nil {
		return nil, NewError(ErrSchemaValidationFailed, 0, "decode policy.json: %v", err)
	}
	pol.PolicySHA256 = hex.EncodeToString(polHash[:])
	pol.RawPolicyBytes = rawBytes

	if pol.SchemaVersion != "mcp-authz-policy/v1" {
		return nil, NewError(ErrSchemaValidationFailed, 0, "unsupported schema_version %q", pol.SchemaVersion)
	}
	if strings.TrimSpace(pol.GatewayID) == "" || strings.TrimSpace(pol.ServerName) == "" {
		return nil, NewError(ErrSchemaValidationFailed, 0, "gateway_id and server_name are required")
	}
	if pol.PinMode != "strict_all" {
		return nil, NewError(ErrManifestPinMismatch, 0, "pin_mode must be \"strict_all\", got %q", pol.PinMode)
	}

	// Validate all TCB and upstream paths
	for _, p := range []string{
		pol.TCB.LockfilePath,
		pol.TCB.StateDBPath,
		pol.TCB.AuditLogPath,
		pol.TCB.ChallengeDir,
		pol.TCB.EmptyHomeDir,
		pol.Upstream.Command,
		pol.Upstream.EnvFile,
	} {
		if err := ValidateCanonicalPath(p); err != nil {
			return nil, err
		}
	}
	for _, optP := range []string{pol.TCB.PolicySigPath, pol.TCB.SSLCertFile, pol.TCB.SSLCertDir} {
		if optP != "" {
			if err := ValidateCanonicalPath(optP); err != nil {
				return nil, err
			}
		}
	}

	// Enforce Mode A / Mode B isolation rules
	if err := VerifyTCBIsolationMode(&pol); err != nil {
		return nil, err
	}
	// If Mode B (in production), verify policyPath itself is owned by root (uid 0)
	if policyPath != "" && pol.TCB.IsolationMode == "mode_b_uid_boundary" {
		pf, _, err := OpenVerifiedFile(policyPath, 0, 0, AllowedConfigUIDs(&pol), 0o022)
		if err != nil {
			return nil, err
		}
		_ = pf.Close()
	}

	if err := ValidateEnvPolicy(&pol.Upstream); err != nil {
		return nil, err
	}
	if pol.Upstream.CallTimeoutMs <= 0 {
		pol.Upstream.CallTimeoutMs = 15000
	}
	if pol.Upstream.MaxOutputBytes <= 0 {
		pol.Upstream.MaxOutputBytes = 4194304
	}

	// Inspect tools for write / high-risk classification
	hasWriteTool := false
	hasHighRiskTool := false
	for toolName, tp := range pol.Tools {
		if tp == nil {
			return nil, NewError(ErrSchemaValidationFailed, 0, "tool %q policy is null", toolName)
		}
		switch tp.ActionClass {
		case "read":
		case "write:low-risk":
			if tp.Enabled {
				hasWriteTool = true
			}
		case "write:high-risk":
			if tp.Enabled {
				hasWriteTool = true
				hasHighRiskTool = true
			}
		default:
			return nil, NewError(ErrSchemaValidationFailed, 0, "tool %q has invalid action_class %q", toolName, tp.ActionClass)
		}
	}

	if hasWriteTool {
		if pol.ReverifyManifestBeforeWrite != nil && !*pol.ReverifyManifestBeforeWrite {
			return nil, NewError(ErrZeroWriteBudgetOnWriteTool, 0, "reverify_manifest_before_write must be true when write tools are enabled")
		}
		if pol.PrincipalAuth.RequireJWT == nil || !*pol.PrincipalAuth.RequireJWT {
			return nil, NewError(ErrWriteToolRequiresJWT, 0, "require_jwt must be true when write tools are enabled")
		}
		if pol.PrincipalAuth.AllowPerCallJWT {
			return nil, NewError(ErrPerCallJWTForbidden, 0, "allow_per_call_jwt is forbidden when write tools are enabled")
		}
		if pol.AgentProfile.MaxWriteCallsPerMinute <= 0 || pol.AgentProfile.MaxWriteTargetsPerWindow <= 0 || pol.AgentProfile.BudgetWindowSeconds < 60 {
			return nil, NewError(ErrZeroWriteBudgetOnWriteTool, 0, "positive write call/target budgets and budget_window_seconds >= 60 are required when write tools are enabled")
		}
	}
	if hasHighRiskTool {
		if pol.AgentProfile.MaxChallengesPerMinute <= 0 {
			return nil, NewError(ErrZeroWriteBudgetOnWriteTool, 0, "positive max_challenges_per_minute is required when write:high-risk tools are enabled")
		}
		if len(pol.StepUp.Approvers) == 0 {
			return nil, NewError(ErrApproverNotAuthorized, 0, "step_up.approvers must be non-empty when write:high-risk tools are enabled")
		}
	}
	if pol.PrincipalAuth.AllowPerCallJWT && pol.AgentProfile.HideUnauthorizedTools {
		return nil, NewError(ErrPerCallJWTForbidden, 0, "allow_per_call_jwt is forbidden when hide_unauthorized_tools is true")
	}

	requireJWT := pol.PrincipalAuth.RequireJWT != nil && *pol.PrincipalAuth.RequireJWT
	if !requireJWT {
		if hasWriteTool || pol.TCB.IsolationMode != "mode_a_read_only" || len(pol.PrincipalAuth.AnonymousScopes) == 0 {
			return nil, NewError(ErrWriteToolRequiresJWT, 0, "require_jwt:false is allowed only in mode_a_read_only with read-only tools and non-empty anonymous_scopes")
		}
	}

	// Validate all scope tokens across policy
	for _, s := range pol.AgentProfile.AllowedScopes {
		if !ValidateScopeToken(s) {
			return nil, NewError(ErrWildcardScopeForbidden, 0, "invalid or wildcard scope %q in agent_profile.allowed_scopes", s)
		}
	}
	for _, s := range pol.PrincipalAuth.AnonymousScopes {
		if !ValidateScopeToken(s) {
			return nil, NewError(ErrWildcardScopeForbidden, 0, "invalid or wildcard scope %q in principal_auth.anonymous_scopes", s)
		}
	}
	for claim, valMap := range pol.PrincipalAuth.ClaimToScopeMap {
		for val, scopes := range valMap {
			for _, s := range scopes {
				if !ValidateScopeToken(s) {
					return nil, NewError(ErrWildcardScopeForbidden, 0, "invalid or wildcard scope %q in claim_to_scope_map[%s][%s]", s, claim, val)
				}
			}
		}
	}

	// Validate and parse all public keys, enforcing no known RFC 8032 test keys and no key reuse across domains.
	seenKeyFingerprints := make(map[string]string)
	pol.ParsedVerifierKeys = make(map[string]*ParsedVerifierKey)

	if pol.TCB.AdminPubKey != "" {
		adminPub, err := ParseEd25519PubKeySpec(pol.TCB.AdminPubKey)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(adminPub)
		fp := "ed25519:" + hex.EncodeToString(sum[:])
		seenKeyFingerprints[fp] = "tcb.admin_pubkey"
	}

	if requireJWT {
		if len(pol.PrincipalAuth.PublicKeys) == 0 {
			return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 0, "principal_auth.public_keys must be non-empty when require_jwt is true")
		}
		for _, alg := range pol.PrincipalAuth.AllowedAlgs {
			if alg != "EdDSA" && alg != "ES256" && alg != "RS256" {
				return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 0, "unsupported JWS algorithm %q in allowed_algs", alg)
			}
		}
		for kid, keySpec := range pol.PrincipalAuth.PublicKeys {
			vk, err := ParseVerifierKeySpec(keySpec)
			if err != nil {
				var ae *AuthzError
				if ok := asAuthzError(err, &ae); ok {
					return nil, ae
				}
				return nil, NewError(ErrPrincipalJWTExpiredOrInvalid, 0, "invalid public_keys[%q]: %v", kid, err)
			}
			if prev, exists := seenKeyFingerprints[vk.Fingerprint]; exists {
				return nil, NewError(ErrKeyReuseForbidden, 0, "key reuse detected between %s and principal_auth.public_keys[%q]", prev, kid)
			}
			seenKeyFingerprints[vk.Fingerprint] = "principal_auth.public_keys[" + kid + "]"
			pol.ParsedVerifierKeys[kid] = vk
		}
		if pol.PrincipalAuth.IdentityClaim == "" {
			pol.PrincipalAuth.IdentityClaim = "sub"
		}
		if pol.PrincipalAuth.IdentityCaseMode == "" {
			pol.PrincipalAuth.IdentityCaseMode = "preserve"
		}
		if pol.PrincipalAuth.IdentityRegex == "" {
			return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "principal_auth.identity_regex is required when require_jwt is true")
		}
		rgx, err := compileAnchoredRegex(pol.PrincipalAuth.IdentityRegex)
		if err != nil {
			return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "invalid principal_auth.identity_regex: %v", err)
		}
		pol.CompiledIdentityRegex = rgx
	}

	// Validate step_up config & approvers
	if pol.StepUp.TicketRegex != "" {
		trgx, err := compileAnchoredRegex(pol.StepUp.TicketRegex)
		if err != nil {
			return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "invalid step_up.ticket_regex: %v", err)
		}
		pol.CompiledTicketRegex = trgx
	}
	for approverSub, appCfg := range pol.StepUp.Approvers {
		if appCfg == nil {
			return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "approver %q config is null", approverSub)
		}
		pub, err := ParseEd25519PubKeySpec(appCfg.PubKey)
		if err != nil {
			var ae *AuthzError
			if ok := asAuthzError(err, &ae); ok {
				return nil, ae
			}
			return nil, NewError(ErrApprovalSignatureInvalid, 0, "invalid approver %q pubkey: %v", approverSub, err)
		}
		sum := sha256.Sum256(pub)
		fp := "ed25519:" + hex.EncodeToString(sum[:])
		if prev, exists := seenKeyFingerprints[fp]; exists {
			return nil, NewError(ErrKeyReuseForbidden, 0, "key reuse detected between %s and step_up.approvers[%q]", prev, approverSub)
		}
		seenKeyFingerprints[fp] = "step_up.approvers[" + approverSub + "]"

		if len(appCfg.PrincipalIDs) == 0 || len(appCfg.Emails) == 0 {
			return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "approver %q must declare non-empty principal_ids and emails", approverSub)
		}
		for _, pid := range appCfg.PrincipalIDs {
			if _, err := NormalizeIdentifier(pid, "id_alnum", pol.CompiledIdentityRegex, pol.PrincipalAuth.IdentityCaseMode); err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "approver %q principal_id %q is non-canonical: %v", approverSub, pid, err)
			}
		}
		for _, em := range appCfg.Emails {
			if _, err := NormalizeIdentifier(em, "email_or_upn", nil, "ascii_lower"); err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "approver %q email %q is non-canonical: %v", approverSub, em, err)
			}
		}
	}

	// Compile protected_resources regexes
	for catName, cat := range pol.ProtectedResources {
		if cat == nil {
			continue
		}
		for _, rStr := range cat.Regexes {
			cr, err := regexp.Compile(rStr)
			if err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "protected_resources[%q] invalid regex %q: %v", catName, rStr, err)
			}
			cat.CompiledRegexes = append(cat.CompiledRegexes, cr)
		}
	}

	// Validate each tool policy and cross-check protected_resources / sod_rules
	for toolName, tp := range pol.Tools {
		for _, s := range tp.RequiredScopes {
			if !ValidateScopeToken(s) {
				return nil, NewError(ErrWildcardScopeForbidden, 0, "tool %q has invalid or wildcard required_scope %q", toolName, s)
			}
		}
		if tp.Enabled && len(tp.RequiredScopes) == 0 {
			return nil, NewError(ErrOBOScopeDenied, 0, "enabled tool %q must declare non-empty required_scopes", toolName)
		}

		isWrite := tp.ActionClass == "write:low-risk" || tp.ActionClass == "write:high-risk"
		if isWrite && tp.Enabled {
			if tp.ForbidSelfTarget == nil {
				return nil, NewError(ErrMissingSelfTargetPolicy, 0, "write tool %q must explicitly set forbid_self_target (true or false)", toolName)
			}
			if *tp.ForbidSelfTarget && len(tp.SubjectTargetBindings) == 0 {
				return nil, NewError(ErrMissingSelfTargetPolicy, 0, "write tool %q with forbid_self_target:true must declare subject_target_bindings", toolName)
			}
			if !ValidatePathExpr(tp.PrimaryTargetPath) {
				return nil, NewError(ErrMissingSelfTargetPolicy, 0, "write tool %q must declare a valid primary_target_path", toolName)
			}
		}

		for i := range tp.SubjectTargetBindings {
			b := &tp.SubjectTargetBindings[i]
			if !ValidatePathExpr(b.Path) || len(b.JWTClaims) == 0 {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q subject_target_binding has invalid path or empty jwt_claims", toolName)
			}
			cr, err := compileAnchoredRegex(b.CanonicalRegex)
			if err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q subject_target_binding %q invalid canonical_regex: %v", toolName, b.Path, err)
			}
			b.CompiledRegex = cr
		}

		for i := range tp.ProtectedTargetBindings {
			b := &tp.ProtectedTargetBindings[i]
			if !ValidatePathExpr(b.Path) || len(b.Categories) == 0 {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q protected_target_binding has invalid path or empty categories", toolName)
			}
			cr, err := compileAnchoredRegex(b.CanonicalRegex)
			if err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q protected_target_binding %q invalid canonical_regex: %v", toolName, b.Path, err)
			}
			b.CompiledRegex = cr
			// Cross-check every exact entry in referenced protected_resources categories!
			for _, catName := range b.Categories {
				cat, exists := pol.ProtectedResources[catName]
				if !exists || cat == nil {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q references undefined protected_resources category %q", toolName, catName)
				}
				for _, exactVal := range cat.Exact {
					if _, err := NormalizeIdentifier(exactVal, b.Normalizer, b.CompiledRegex, b.CaseMode); err != nil {
						return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "protected_resources[%q].exact entry %q fails binding (%s, %s) on tool %q: %v", catName, exactVal, b.Normalizer, b.CanonicalRegex, toolName, err)
					}
				}
			}
		}

		if tp.SoDBinding != nil {
			sb := tp.SoDBinding
			if !ValidatePathExpr(sb.SubjectPath) || !ValidatePathExpr(sb.EntitlementPath) {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q sod_binding has invalid subject_path or entitlement_path", toolName)
			}
			subRgx, err := compileAnchoredRegex(sb.SubjectCanonicalRegex)
			if err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q sod_binding invalid subject_canonical_regex: %v", toolName, err)
			}
			entRgx, err := compileAnchoredRegex(sb.EntitlementCanonicalRegex)
			if err != nil {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q sod_binding invalid entitlement_canonical_regex: %v", toolName, err)
			}
			sb.CompiledSubjectRegex = subRgx
			sb.CompiledEntitlementCanonRegex = entRgx

			// Validate all sod_rules and subject_existing_entitlements against this sod_binding
			for _, rule := range pol.SoDRules {
				if len(rule.ConflictingEntitlements) < 2 {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "sod_rule %q must have >= 2 conflicting_entitlements", rule.RuleID)
				}
				for _, ent := range rule.ConflictingEntitlements {
					if _, err := NormalizeIdentifier(ent, sb.EntitlementNormalizer, sb.CompiledEntitlementCanonRegex, sb.EntitlementCaseMode); err != nil {
						return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "sod_rule %q entitlement %q fails sod_binding canonical check: %v", rule.RuleID, ent, err)
					}
				}
			}
			for subj, ents := range pol.SubjectExistingEntitlements {
				if _, err := NormalizeIdentifier(subj, sb.SubjectNormalizer, sb.CompiledSubjectRegex, sb.SubjectCaseMode); err != nil {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "subject_existing_entitlements subject %q fails canonical check: %v", subj, err)
				}
				for _, ent := range ents {
					if _, err := NormalizeIdentifier(ent, sb.EntitlementNormalizer, sb.CompiledEntitlementCanonRegex, sb.EntitlementCaseMode); err != nil {
						return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "subject_existing_entitlements[%q] entitlement %q fails canonical check: %v", subj, ent, err)
					}
				}
			}
		}

		for _, ac := range tp.ArrayCapBindings {
			if !ValidatePathExpr(ac.Path) || ac.MaxItems <= 0 || ac.MaxItems > 1000 {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q array_cap_binding %q has invalid path or max_items", toolName, ac.Path)
			}
		}
		for _, lb := range tp.LimitArgBindings {
			if !ValidatePathExpr(lb.Path) || lb.DefaultValue < 1 || lb.MaxValue < lb.DefaultValue {
				return nil, NewError(ErrBlastRadiusLimitExceeded, 0, "tool %q limit_arg_binding %q must satisfy 1 <= default_value (%d) <= max_value (%d)", toolName, lb.Path, lb.DefaultValue, lb.MaxValue)
			}
		}
		for _, rp := range tp.RedactArgs {
			if !ValidatePathExpr(rp) {
				return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q redact_args entry %q is not a valid PathExpr", toolName, rp)
			}
		}
		if tp.ArgConstraints != nil {
			for _, reqP := range tp.ArgConstraints.RequiredNonEmpty {
				if !ValidatePathExpr(reqP) {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints required_non_empty invalid path %q", toolName, reqP)
				}
			}
			for _, optP := range tp.ArgConstraints.OptionalPaths {
				if !ValidatePathExpr(optP) {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints optional_paths invalid path %q", toolName, optP)
				}
			}
			for numP, nb := range tp.ArgConstraints.NumericBounds {
				if !ValidatePathExpr(numP) {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints numeric_bounds invalid path %q", toolName, numP)
				}
				if nb.Min != nil && nb.Max != nil && *nb.Min > *nb.Max {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints numeric_bounds[%q] min (%v) > max (%v)", toolName, numP, *nb.Min, *nb.Max)
				}
			}
			for enumP, allow := range tp.ArgConstraints.EnumAllowlist {
				if !ValidatePathExpr(enumP) || len(allow) == 0 {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints enum_allowlist[%q] has invalid path or empty allowlist", toolName, enumP)
				}
			}
			tp.ArgConstraints.CompiledRegexes = make(map[string]*regexp.Regexp)
			for p, rStr := range tp.ArgConstraints.RegexMatch {
				if !ValidatePathExpr(p) {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints regex_match invalid path %q", toolName, p)
				}
				cr, err := compileAnchoredRegex(rStr)
				if err != nil {
					return nil, NewError(ErrPolicyIdentifierNonCanonical, 0, "tool %q arg_constraints regex_match[%q] invalid: %v", toolName, p, err)
				}
				tp.ArgConstraints.CompiledRegexes[p] = cr
			}
		}
	}

	return &pol, nil
}

func compileAnchoredRegex(pattern string) (*regexp.Regexp, error) {
	if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		return nil, fmt.Errorf("regex %q must be anchored with ^ and $", pattern)
	}
	return regexp.Compile(pattern)
}

func asAuthzError(err error, target **AuthzError) bool {
	if err == nil {
		return false
	}
	if ae, ok := err.(*AuthzError); ok {
		*target = ae
		return true
	}
	return false
}

// ValidatePathExpr validates the restricted PathExpr grammar (<= 4 segments, <= 1 '[*]').
func ValidatePathExpr(expr string) bool {
	if !pathExprRegex.MatchString(expr) {
		return false
	}
	segments := strings.Split(expr, ".")
	if len(segments) > 4 {
		return false
	}
	if strings.Count(expr, "[*]") > 1 {
		return false
	}
	return true
}

// ExtractStrings extracts leaf string values at expr from obj according to §4.3.3.
func ExtractStrings(obj map[string]any, expr string, optional bool) ([]string, error) {
	if !ValidatePathExpr(expr) {
		return nil, NewError(ErrArgumentTypeInvalid, 3, "invalid PathExpr %q", expr)
	}
	segments := strings.Split(expr, ".")
	return extractFromSegments(obj, segments, optional)
}

func extractFromSegments(curr any, segments []string, optional bool) ([]string, error) {
	if len(segments) == 0 {
		s, ok := curr.(string)
		if !ok {
			return nil, NewError(ErrArgumentTypeInvalid, 3, "expected string leaf value, got %T", curr)
		}
		if strings.TrimSpace(s) == "" {
			return nil, NewError(ErrRequiredTargetArgMissing, 3, "target string argument cannot be empty or whitespace")
		}
		return []string{s}, nil
	}

	seg := segments[0]
	rest := segments[1:]
	isWildcard := strings.HasSuffix(seg, "[*]")
	fieldName := strings.TrimSuffix(seg, "[*]")

	m, ok := curr.(map[string]any)
	if !ok {
		return nil, NewError(ErrArgumentTypeInvalid, 3, "expected object before segment %q, got %T", seg, curr)
	}
	val, exists := m[fieldName]
	if !exists || val == nil {
		if optional {
			return nil, nil
		}
		return nil, NewError(ErrRequiredTargetArgMissing, 3, "missing required target argument at %q", fieldName)
	}

	if !isWildcard {
		return extractFromSegments(val, rest, optional)
	}

	arr, ok := val.([]any)
	if !ok {
		return nil, NewError(ErrArgumentTypeInvalid, 3, "expected array at %q, got %T", seg, val)
	}
	if len(arr) == 0 {
		return nil, NewError(ErrRequiredTargetArgMissing, 3, "array at %q cannot be empty", seg)
	}
	if len(arr) > 1000 {
		return nil, NewError(ErrBlastRadiusArrayCap, 3, "array at %q length %d exceeds hard cap 1000", seg, len(arr))
	}

	out := make([]string, 0, len(arr))
	for _, elem := range arr {
		if elem == nil {
			return nil, NewError(ErrRequiredTargetArgMissing, 3, "null element inside array %q", seg)
		}
		// Inside a present array, every element MUST resolve the leaf string (optional=false).
		subVals, err := extractFromSegments(elem, rest, false)
		if err != nil {
			return nil, err
		}
		out = append(out, subVals...)
	}
	return out, nil
}

// NormalizeIdentifier applies the §4.3.3 character-allowlist normalizer, reserved self-alias
// check, case_mode transformation, and optional canonicalRegex check.
func NormalizeIdentifier(raw string, normalizer string, canonicalRegex *regexp.Regexp, caseMode string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) == "" {
		return "", NewError(ErrInvalidIdentifierChars, 3, "identifier is empty or whitespace")
	}
	// Reject non-ASCII or control characters
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b >= 0x7F {
			return "", NewError(ErrInvalidIdentifierChars, 3, "identifier contains non-ASCII or control byte 0x%02x", b)
		}
	}
	if reservedSelfNames[asciiLower(strings.TrimSpace(raw))] {
		return "", NewError(ErrInvalidIdentifierChars, 3, "reserved self-alias %q is forbidden", raw)
	}

	switch normalizer {
	case "id_alnum":
		if raw == "." || raw == ".." || strings.Contains(raw, "..") || !idAlnumRegex.MatchString(raw) {
			return "", NewError(ErrInvalidIdentifierChars, 3, "identifier %q failed id_alnum allowlist", raw)
		}
	case "email_or_upn":
		if strings.Contains(raw, "..") || !emailOrUPNRegex.MatchString(raw) {
			return "", NewError(ErrInvalidIdentifierChars, 3, "identifier %q failed email_or_upn allowlist", raw)
		}
	case "uuid":
		if !uuidCanonicalRgx.MatchString(raw) {
			return "", NewError(ErrInvalidIdentifierChars, 3, "identifier %q failed uuid allowlist", raw)
		}
	case "dn_exact":
		if !dnExactRegex.MatchString(raw) {
			return "", NewError(ErrInvalidIdentifierChars, 3, "identifier %q failed dn_exact allowlist", raw)
		}
	default:
		return "", NewError(ErrInvalidIdentifierChars, 3, "unsupported normalizer %q", normalizer)
	}

	var out string
	switch caseMode {
	case "", "preserve":
		out = raw
	case "ascii_lower":
		out = asciiLower(raw)
	case "ascii_upper":
		out = asciiUpper(raw)
	default:
		return "", NewError(ErrInvalidIdentifierChars, 3, "unsupported case_mode %q", caseMode)
	}

	if canonicalRegex != nil && !canonicalRegex.MatchString(out) {
		return "", NewError(ErrNonCanonicalIdentifier, 3, "identifier %q does not match canonical_regex %q", out, canonicalRegex.String())
	}
	return out, nil
}

// EvaluateStage3Guardrails runs all Stage 3 checks (target extraction, normalization, canonical_regex,
// Tier-0 denylist, forbid_self_target, intra-call & static SoD, array caps, limit caps, arg_constraints)
// and returns (primaryTargetCount, canonicalSoDSubjects, canonicalSoDEntitlements, error).
func EvaluateStage3Guardrails(
	pol *PolicyV1,
	tp *ToolPolicy,
	cleanArgs map[string]any,
	pctx *PrincipalContext,
	ledgerGrants map[string]map[string]struct{},
) (int, []string, []string, error) {
	isWrite := tp.ActionClass == "write:low-risk" || tp.ActionClass == "write:high-risk"

	// 1. Primary target path extraction & count for write tools
	primaryTargetCount := 0
	if isWrite {
		primTargets, err := ExtractStrings(cleanArgs, tp.PrimaryTargetPath, false)
		if err != nil {
			return 0, nil, nil, err
		}
		primaryTargetCount = len(primTargets)
		if primaryTargetCount < 1 {
			return 0, nil, nil, NewError(ErrRequiredTargetArgMissing, 3, "primary_target_path %q extracted 0 targets", tp.PrimaryTargetPath)
		}
	}

	// 2. Protected Target Bindings (Tier-0 Protection)
	for _, b := range tp.ProtectedTargetBindings {
		vals, err := ExtractStrings(cleanArgs, b.Path, b.Optional)
		if err != nil {
			return 0, nil, nil, err
		}
		for _, rawVal := range vals {
			normVal, err := NormalizeIdentifier(rawVal, b.Normalizer, b.CompiledRegex, b.CaseMode)
			if err != nil {
				return 0, nil, nil, err
			}
			for _, catName := range b.Categories {
				cat := pol.ProtectedResources[catName]
				if cat == nil {
					continue
				}
				if matchProtectedCategory(normVal, cat) {
					return 0, nil, nil, NewError(ErrTier0ProtectedTarget, 3, "argument %q target %q matches protected Tier-0 category %q", b.Path, normVal, catName)
				}
			}
		}
	}

	// 3. Subject Target Bindings & Self-Dealing Prevention
	for _, b := range tp.SubjectTargetBindings {
		vals, err := ExtractStrings(cleanArgs, b.Path, b.Optional)
		if err != nil {
			return 0, nil, nil, err
		}
		normTargets := make([]string, 0, len(vals))
		for _, rawVal := range vals {
			nv, err := NormalizeIdentifier(rawVal, b.Normalizer, b.CompiledRegex, b.CaseMode)
			if err != nil {
				return 0, nil, nil, err
			}
			normTargets = append(normTargets, nv)
		}

		if tp.ForbidSelfTarget != nil && *tp.ForbidSelfTarget {
			if pctx == nil || pctx.Anonymous {
				return 0, nil, nil, NewError(ErrSelfDealingClaimMissing, 3, "forbid_self_target requires an authenticated JWT principal")
			}
			callerTokens := make(map[string]struct{})
			for _, claimKey := range b.JWTClaims {
				rawClaim, exists := pctx.Claims[claimKey]
				if !exists || rawClaim == nil {
					return 0, nil, nil, NewError(ErrSelfDealingClaimMissing, 3, "JWT missing required self-dealing claim %q", claimKey)
				}
				claimStr, ok := rawClaim.(string)
				if !ok || strings.TrimSpace(claimStr) == "" {
					return 0, nil, nil, NewError(ErrSelfDealingClaimMissing, 3, "JWT self-dealing claim %q must be a non-empty string", claimKey)
				}
				normClaim, err := NormalizeIdentifier(claimStr, b.Normalizer, b.CompiledRegex, b.CaseMode)
				if err != nil {
					return 0, nil, nil, NewError(ErrSelfDealingClaimMissing, 3, "JWT self-dealing claim %q failed normalization: %v", claimKey, err)
				}
				callerTokens[normClaim] = struct{}{}
			}
			for _, nt := range normTargets {
				if _, isSelf := callerTokens[nt]; isSelf {
					return 0, nil, nil, NewError(ErrSelfDealingForbidden, 3, "caller is forbidden from targeting own identity %q at %q", nt, b.Path)
				}
			}
		}
	}

	// 4. Separation of Duties (SoD) Evaluation
	var sodSubjects, sodEntitlements []string
	if tp.SoDBinding != nil {
		sb := tp.SoDBinding
		rawSubjs, err := ExtractStrings(cleanArgs, sb.SubjectPath, false)
		if err != nil {
			return 0, nil, nil, err
		}
		for _, rs := range rawSubjs {
			ns, err := NormalizeIdentifier(rs, sb.SubjectNormalizer, sb.CompiledSubjectRegex, sb.SubjectCaseMode)
			if err != nil {
				return 0, nil, nil, err
			}
			sodSubjects = append(sodSubjects, ns)
		}

		rawEnts, err := ExtractStrings(cleanArgs, sb.EntitlementPath, false)
		if err != nil {
			return 0, nil, nil, err
		}
		for _, re := range rawEnts {
			ne, err := NormalizeIdentifier(re, sb.EntitlementNormalizer, sb.CompiledEntitlementCanonRegex, sb.EntitlementCaseMode)
			if err != nil {
				return 0, nil, nil, err
			}
			sodEntitlements = append(sodEntitlements, ne)
		}

		if err := CheckSoDRules(pol, sodSubjects, sodEntitlements, ledgerGrants); err != nil {
			return 0, nil, nil, err
		}
	}

	// 5. Blast-Radius Array Caps
	for _, ac := range tp.ArrayCapBindings {
		if err := checkArrayCapAtPath(cleanArgs, strings.Split(ac.Path, "."), ac.MaxItems); err != nil {
			return 0, nil, nil, err
		}
	}

	// 6. Pagination / Limit Caps
	for _, lb := range tp.LimitArgBindings {
		if err := checkLimitCapAtPath(cleanArgs, strings.Split(lb.Path, "."), lb.MaxValue); err != nil {
			return 0, nil, nil, err
		}
	}

	// 7. Argument Value Constraints
	if tp.ArgConstraints != nil {
		if err := evaluateArgConstraints(cleanArgs, tp.ArgConstraints); err != nil {
			return 0, nil, nil, err
		}
	}

	return primaryTargetCount, sodSubjects, sodEntitlements, nil
}

// CheckSoDRules evaluates intra-call, static baseline, and permanent state.db ledger grants against pol.SoDRules.
// Requires E_req ∩ C != ∅ AND |(E_req ∪ E_static(u) ∪ E_ledger(u)) ∩ C| >= 2.
func CheckSoDRules(pol *PolicyV1, subjects []string, requestedEntitlements []string, ledgerGrants map[string]map[string]struct{}) error {
	for _, subj := range subjects {
		for _, rule := range pol.SoDRules {
			conflictSet := make(map[string]struct{}, len(rule.ConflictingEntitlements))
			for _, ce := range rule.ConflictingEntitlements {
				key := ce
				if rule.CaseInsensitive {
					key = asciiLower(ce)
				}
				conflictSet[key] = struct{}{}
			}

			// First check if E_req intersects C
			reqIntersects := false
			matched := make(map[string]struct{})
			for _, reqEnt := range requestedEntitlements {
				key := reqEnt
				if rule.CaseInsensitive {
					key = asciiLower(reqEnt)
				}
				if _, inC := conflictSet[key]; inC {
					reqIntersects = true
					matched[key] = struct{}{}
				}
			}
			if !reqIntersects {
				continue
			}

			// Union static baseline entitlements for subj
			for sKey, staticEnts := range pol.SubjectExistingEntitlements {
				subjMatch := sKey == subj || (rule.CaseInsensitive && asciiLower(sKey) == asciiLower(subj))
				if !subjMatch {
					continue
				}
				for _, se := range staticEnts {
					key := se
					if rule.CaseInsensitive {
						key = asciiLower(se)
					}
					if _, inC := conflictSet[key]; inC {
						matched[key] = struct{}{}
					}
				}
			}

			// Union permanent ledger grants for subj
			for lSubj, grantSet := range ledgerGrants {
				subjMatch := lSubj == subj || (rule.CaseInsensitive && asciiLower(lSubj) == asciiLower(subj))
				if !subjMatch {
					continue
				}
				for ge := range grantSet {
					key := ge
					if rule.CaseInsensitive {
						key = asciiLower(ge)
					}
					if _, inC := conflictSet[key]; inC {
						matched[key] = struct{}{}
					}
				}
			}

			if len(matched) >= 2 {
				return NewError(ErrSoDConflictDetected, 3, "SoD rule %q violated for subject %q", rule.RuleID, subj)
			}
		}
	}
	return nil
}

func matchProtectedCategory(normVal string, cat *ProtectedCategory) bool {
	cmpVal := normVal
	if cat.CaseInsensitive {
		cmpVal = asciiLower(normVal)
	}
	for _, ex := range cat.Exact {
		target := ex
		if cat.CaseInsensitive {
			target = asciiLower(ex)
		}
		if cmpVal == target {
			return true
		}
	}
	for _, pfx := range cat.Prefixes {
		target := pfx
		if cat.CaseInsensitive {
			target = asciiLower(pfx)
		}
		if strings.HasPrefix(cmpVal, target) {
			return true
		}
	}
	for _, rgx := range cat.CompiledRegexes {
		if rgx.MatchString(normVal) {
			return true
		}
	}
	return false
}

func checkArrayCapAtPath(curr any, segments []string, maxItems int) error {
	if len(segments) == 0 {
		arr, ok := curr.([]any)
		if !ok {
			return NewError(ErrArgumentTypeInvalid, 3, "array_cap_binding target is not an array")
		}
		if len(arr) > maxItems {
			return NewError(ErrBlastRadiusArrayCap, 3, "array length %d exceeds max_items %d", len(arr), maxItems)
		}
		return nil
	}
	seg := segments[0]
	rest := segments[1:]
	isWildcard := strings.HasSuffix(seg, "[*]")
	fieldName := strings.TrimSuffix(seg, "[*]")
	m, ok := curr.(map[string]any)
	if !ok {
		return nil
	}
	val, exists := m[fieldName]
	if !exists || val == nil {
		return nil
	}
	if isWildcard && len(rest) > 0 {
		arr, ok := val.([]any)
		if !ok {
			return NewError(ErrArgumentTypeInvalid, 3, "array_cap_binding intermediate segment %q is not an array", seg)
		}
		if len(arr) > 1000 {
			return NewError(ErrBlastRadiusArrayCap, 3, "array at %q length %d exceeds hard cap 1000", seg, len(arr))
		}
		for _, elem := range arr {
			if err := checkArrayCapAtPath(elem, rest, maxItems); err != nil {
				return err
			}
		}
		return nil
	}
	return checkArrayCapAtPath(val, rest, maxItems)
}

func checkLimitCapAtPath(curr any, segments []string, maxVal int) error {
	if len(segments) == 0 {
		f, ok := curr.(float64)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) || math.Trunc(f) != f {
			return NewError(ErrBlastRadiusLimitExceeded, 3, "limit argument must be an integer")
		}
		if f < 1 || f > float64(maxVal) {
			return NewError(ErrBlastRadiusLimitExceeded, 3, "limit %v outside allowed range [1, %d]", f, maxVal)
		}
		return nil
	}
	seg := segments[0]
	rest := segments[1:]
	isWildcard := strings.HasSuffix(seg, "[*]")
	fieldName := strings.TrimSuffix(seg, "[*]")
	m, ok := curr.(map[string]any)
	if !ok {
		return nil
	}
	val, exists := m[fieldName]
	if !exists || val == nil {
		return nil
	}
	if isWildcard {
		arr, ok := val.([]any)
		if !ok {
			return NewError(ErrArgumentTypeInvalid, 3, "limit_arg_binding segment %q is not an array", seg)
		}
		if len(arr) > 1000 {
			return NewError(ErrBlastRadiusArrayCap, 3, "array at %q length %d exceeds hard cap 1000", seg, len(arr))
		}
		for _, elem := range arr {
			if elem == nil {
				return NewError(ErrBlastRadiusLimitExceeded, 3, "null element inside limit array %q", seg)
			}
			if err := checkLimitCapAtPath(elem, rest, maxVal); err != nil {
				return err
			}
		}
		return nil
	}
	return checkLimitCapAtPath(val, rest, maxVal)
}

func evaluateArgConstraints(cleanArgs map[string]any, ac *ArgConstraints) error {
	optSet := make(map[string]bool, len(ac.OptionalPaths))
	for _, p := range ac.OptionalPaths {
		optSet[p] = true
	}

	for _, reqPath := range ac.RequiredNonEmpty {
		vals, err := ExtractStrings(cleanArgs, reqPath, false)
		if err != nil || len(vals) == 0 {
			return NewError(ErrArgumentConstraintViolated, 3, "required_non_empty constraint failed at %q", reqPath)
		}
	}

	for path, rgx := range ac.CompiledRegexes {
		vals, err := ExtractStrings(cleanArgs, path, optSet[path])
		if err != nil {
			return NewError(ErrArgumentConstraintViolated, 3, "regex_match path %q extraction failed: %v", path, err)
		}
		for _, v := range vals {
			if !rgx.MatchString(v) {
				return NewError(ErrArgumentConstraintViolated, 3, "argument %q value %q failed regex_match", path, v)
			}
		}
	}

	for path, allowed := range ac.EnumAllowlist {
		vals, err := ExtractStrings(cleanArgs, path, optSet[path])
		if err != nil {
			return NewError(ErrArgumentConstraintViolated, 3, "enum_allowlist path %q extraction failed: %v", path, err)
		}
		for _, v := range vals {
			if !slices.Contains(allowed, v) {
				return NewError(ErrArgumentConstraintViolated, 3, "argument %q value %q not in enum_allowlist", path, v)
			}
		}
	}

	for path, bounds := range ac.NumericBounds {
		nums, err := extractNumbersFromSegments(cleanArgs, strings.Split(path, "."), optSet[path])
		if err != nil {
			return err
		}
		for _, f := range nums {
			if bounds.Min != nil && f < *bounds.Min {
				return NewError(ErrArgumentConstraintViolated, 3, "argument %q value %v < min %v", path, f, *bounds.Min)
			}
			if bounds.Max != nil && f > *bounds.Max {
				return NewError(ErrArgumentConstraintViolated, 3, "argument %q value %v > max %v", path, f, *bounds.Max)
			}
		}
	}
	return nil
}

func extractNumbersFromSegments(curr any, segments []string, optional bool) ([]float64, error) {
	if len(segments) == 0 {
		f, ok := curr.(float64)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, NewError(ErrArgumentConstraintViolated, 3, "numeric_bounds leaf value must be a number, got %T", curr)
		}
		return []float64{f}, nil
	}
	seg := segments[0]
	rest := segments[1:]
	isWildcard := strings.HasSuffix(seg, "[*]")
	fieldName := strings.TrimSuffix(seg, "[*]")

	m, ok := curr.(map[string]any)
	if !ok {
		return nil, NewError(ErrArgumentConstraintViolated, 3, "expected object before segment %q, got %T", seg, curr)
	}
	val, exists := m[fieldName]
	if !exists || val == nil {
		if optional {
			return nil, nil
		}
		return nil, NewError(ErrArgumentConstraintViolated, 3, "missing numeric_bounds argument %q", fieldName)
	}
	if !isWildcard {
		return extractNumbersFromSegments(val, rest, optional)
	}
	arr, ok := val.([]any)
	if !ok {
		return nil, NewError(ErrArgumentConstraintViolated, 3, "expected array at %q, got %T", seg, val)
	}
	if len(arr) == 0 {
		if optional {
			return nil, nil
		}
		return nil, NewError(ErrArgumentConstraintViolated, 3, "numeric_bounds array at %q cannot be empty", seg)
	}
	if len(arr) > 1000 {
		return nil, NewError(ErrBlastRadiusArrayCap, 3, "array at %q length %d exceeds hard cap 1000", seg, len(arr))
	}
	out := make([]float64, 0, len(arr))
	for _, elem := range arr {
		if elem == nil {
			return nil, NewError(ErrArgumentConstraintViolated, 3, "null element inside numeric_bounds array %q", seg)
		}
		subNums, err := extractNumbersFromSegments(elem, rest, false)
		if err != nil {
			return nil, err
		}
		out = append(out, subNums...)
	}
	return out, nil
}

// ExtractAndStripApprovalToken extracts the step-up approval token from arguments["__mcp_authz_approval_token"]
// and/or request _meta["io.identity-mcp/approval_token"], strips the argument from argsMap,
// and rejects conflicting values with AMBIGUOUS_APPROVAL_TOKEN.
func ExtractAndStripApprovalToken(argsMap map[string]any, reqMeta map[string]any, isHighRisk bool) (string, error) {
	var argTok string
	var hasArgTok bool
	if isHighRisk {
		if raw, exists := argsMap[ApprovalTokenArgName]; exists {
			delete(argsMap, ApprovalTokenArgName)
			if raw != nil {
				s, ok := raw.(string)
				if !ok {
					return "", NewError(ErrApprovalSignatureInvalid, 4, "%s must be a string", ApprovalTokenArgName)
				}
				argTok = s
				hasArgTok = true
			}
		}
	}

	var metaTok string
	var hasMetaTok bool
	if reqMeta != nil {
		if raw, exists := reqMeta["io.identity-mcp/approval_token"]; exists && raw != nil {
			s, ok := raw.(string)
			if !ok {
				return "", NewError(ErrApprovalSignatureInvalid, 4, "_meta[\"io.identity-mcp/approval_token\"] must be a string")
			}
			metaTok = s
			hasMetaTok = true
		}
	}

	if hasArgTok && hasMetaTok && argTok != metaTok {
		return "", NewError(ErrAmbiguousApprovalToken, 4, "approval token in arguments differs from _meta[\"io.identity-mcp/approval_token\"]")
	}
	if hasArgTok {
		return argTok, nil
	}
	return metaTok, nil
}

// InjectLimitDefaults populates default_value for any absent or null limit_arg_binding path.
func InjectLimitDefaults(argsMap map[string]any, bindings []LimitArgBinding) {
	for _, lb := range bindings {
		segments := strings.Split(lb.Path, ".")
		injectDefaultAtSegments(argsMap, segments, float64(lb.DefaultValue))
	}
}

func injectDefaultAtSegments(curr map[string]any, segments []string, defVal float64) {
	if len(segments) == 1 {
		fieldName := strings.TrimSuffix(segments[0], "[*]")
		if existing, ok := curr[fieldName]; !ok || existing == nil {
			curr[fieldName] = defVal
		}
		return
	}
	seg := segments[0]
	isWildcard := strings.HasSuffix(seg, "[*]")
	fieldName := strings.TrimSuffix(seg, "[*]")
	if isWildcard {
		arr, ok := curr[fieldName].([]any)
		if !ok {
			return
		}
		for _, elem := range arr {
			if elemMap, ok := elem.(map[string]any); ok {
				injectDefaultAtSegments(elemMap, segments[1:], defVal)
			}
		}
		return
	}
	next, ok := curr[fieldName].(map[string]any)
	if !ok {
		return
	}
	injectDefaultAtSegments(next, segments[1:], defVal)
}

// CheckUnknownToolArguments recursively rejects any key in argsMap not declared in schemaMap.properties.
func CheckUnknownToolArguments(argsMap map[string]any, schemaMap map[string]any) error {
	props, _ := schemaMap["properties"].(map[string]any)
	for k, v := range argsMap {
		propSchema, declared := props[k].(map[string]any)
		if !declared {
			return NewError(ErrUnknownToolArgument, 1, "unknown tool argument %q", k)
		}
		if subObj, isObj := v.(map[string]any); isObj {
			if err := CheckUnknownToolArguments(subObj, propSchema); err != nil {
				return err
			}
		} else if subArr, isArr := v.([]any); isArr {
			if itemsSchema, ok := propSchema["items"].(map[string]any); ok {
				for _, elem := range subArr {
					if elemObj, isElemObj := elem.(map[string]any); isElemObj {
						if err := CheckUnknownToolArguments(elemObj, itemsSchema); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

var allowedSchemaKeywords = map[string]bool{
	"$schema":              true,
	"type":                 true,
	"title":                true,
	"description":          true,
	"properties":           true,
	"required":             true,
	"additionalProperties": true,
	"items":                true,
	"enum":                 true,
	"const":                true,
	"minimum":              true,
	"maximum":              true,
	"minLength":            true,
	"maxLength":            true,
	"minItems":             true,
	"maxItems":             true,
	"pattern":              true,
	"format":               true,
	"default":              true,
}

// ValidateUpstreamInputSchema enforces §4.5.3 on an upstream tool's inputSchema.
func ValidateUpstreamInputSchema(schemaMap map[string]any, isWriteTool bool, boundPaths map[string]bool) error {
	if schemaMap == nil {
		return NewError(ErrUpstreamSchemaUnsupported, 0, "inputSchema cannot be null")
	}
	rootType, _ := schemaMap["type"].(string)
	if rootType != "object" {
		return NewError(ErrUpstreamSchemaUnsupported, 0, "inputSchema root must have \"type\": \"object\"")
	}
	if props, ok := schemaMap["properties"].(map[string]any); ok {
		for propName := range props {
			if asciiLower(propName) == ApprovalTokenArgName {
				return NewError(ErrReservedArgumentCollision, 0, "upstream inputSchema property %q collides with reserved approval token argument", propName)
			}
		}
	}
	return walkSchemaSubset(schemaMap, "", false, isWriteTool, boundPaths)
}

// ValidateUpstreamOutputSchema enforces §4.5.3 on an upstream tool's outputSchema.
func ValidateUpstreamOutputSchema(schemaMap map[string]any) error {
	if schemaMap == nil {
		return nil
	}
	return walkSchemaSubset(schemaMap, "", true, false, nil)
}

func walkSchemaSubset(node map[string]any, currentPath string, isOutputSchema bool, isWriteTool bool, boundPaths map[string]bool) error {
	for k := range node {
		if !allowedSchemaKeywords[k] {
			return NewError(ErrUpstreamSchemaUnsupported, 0, "unsupported JSON Schema keyword %q at %q", k, currentPath)
		}
	}
	if _, hasDefault := node["default"]; hasDefault && !isOutputSchema {
		if isWriteTool || boundPaths[currentPath] {
			return NewError(ErrUpstreamSchemaDefaultForbidden, 0, "JSON Schema \"default\" keyword is forbidden at %q", currentPath)
		}
	}

	// Validate "type"
	typeVal, hasType := node["type"]
	if !hasType {
		return NewError(ErrUpstreamSchemaUnsupported, 0, "schema node at %q missing explicit \"type\"", currentPath)
	}
	effectiveType, err := parseAllowedSchemaType(typeVal, isOutputSchema, currentPath)
	if err != nil {
		return err
	}

	if ap, hasAP := node["additionalProperties"]; hasAP {
		if isOutputSchema {
			switch apVal := ap.(type) {
			case bool:
			case map[string]any:
				if err := walkSchemaSubset(apVal, currentPath+".*", true, false, nil); err != nil {
					return err
				}
			default:
				return NewError(ErrUpstreamSchemaUnsupported, 0, "invalid additionalProperties at %q", currentPath)
			}
		} else {
			b, isBool := ap.(bool)
			if !isBool || b {
				return NewError(ErrUpstreamSchemaUnsupported, 0, "inputSchema additionalProperties at %q must be false", currentPath)
			}
		}
	}

	if effectiveType == "object" {
		if props, ok := node["properties"].(map[string]any); ok {
			for propName, rawProp := range props {
				propMap, isMap := rawProp.(map[string]any)
				if !isMap {
					return NewError(ErrUpstreamSchemaUnsupported, 0, "property %q at %q is not a schema object", propName, currentPath)
				}
				childPath := propName
				if currentPath != "" {
					childPath = currentPath + "." + propName
				}
				if err := walkSchemaSubset(propMap, childPath, isOutputSchema, isWriteTool, boundPaths); err != nil {
					return err
				}
			}
		}
	}

	if effectiveType == "array" {
		itemsMap, ok := node["items"].(map[string]any)
		if !ok {
			return NewError(ErrUpstreamSchemaUnsupported, 0, "array schema at %q must declare an \"items\" object", currentPath)
		}
		childPath := currentPath + "[*]"
		if err := walkSchemaSubset(itemsMap, childPath, isOutputSchema, isWriteTool, boundPaths); err != nil {
			return err
		}
	}
	return nil
}

func parseAllowedSchemaType(typeVal any, isOutputSchema bool, currentPath string) (string, error) {
	switch tv := typeVal.(type) {
	case string:
		switch tv {
		case "object", "array", "string", "integer", "number", "boolean":
			return tv, nil
		default:
			return "", NewError(ErrUpstreamSchemaUnsupported, 0, "unsupported schema type %q at %q", tv, currentPath)
		}
	case []any:
		if len(tv) == 2 {
			s0, ok0 := tv[0].(string)
			s1, ok1 := tv[1].(string)
			if ok0 && ok1 {
				nonNull := ""
				if s0 == "null" {
					nonNull = s1
				} else if s1 == "null" {
					nonNull = s0
				}
				if isOutputSchema {
					switch nonNull {
					case "object", "array", "string", "integer", "number", "boolean":
						return nonNull, nil
					}
				} else if nonNull == "array" {
					return "array", nil
				}
			}
		}
		return "", NewError(ErrUpstreamSchemaUnsupported, 0, "unsupported schema type union %v at %q", tv, currentPath)
	default:
		return "", NewError(ErrUpstreamSchemaUnsupported, 0, "invalid schema type %T at %q", typeVal, currentPath)
	}
}

// CollectToolBoundPaths returns all PathExpr strings referenced by a ToolPolicy.
func CollectToolBoundPaths(tp *ToolPolicy) map[string]bool {
	out := make(map[string]bool)
	if tp == nil {
		return out
	}
	if tp.PrimaryTargetPath != "" {
		out[tp.PrimaryTargetPath] = true
	}
	for _, b := range tp.SubjectTargetBindings {
		out[b.Path] = true
	}
	for _, b := range tp.ProtectedTargetBindings {
		out[b.Path] = true
	}
	if tp.SoDBinding != nil {
		out[tp.SoDBinding.SubjectPath] = true
		out[tp.SoDBinding.EntitlementPath] = true
	}
	for _, b := range tp.ArrayCapBindings {
		out[b.Path] = true
	}
	for _, b := range tp.LimitArgBindings {
		out[b.Path] = true
	}
	if tp.ArgConstraints != nil {
		for _, p := range tp.ArgConstraints.RequiredNonEmpty {
			out[p] = true
		}
		for p := range tp.ArgConstraints.RegexMatch {
			out[p] = true
		}
		for p := range tp.ArgConstraints.NumericBounds {
			out[p] = true
		}
		for p := range tp.ArgConstraints.EnumAllowlist {
			out[p] = true
		}
	}
	return out
}

// ValidatePolicyPathsAgainstSchema verifies that every policy-bound PathExpr resolves in inputSchema
// with the expected leaf type (string for targets/SoD, integer/number for limits, array for array caps).
func ValidatePolicyPathsAgainstSchema(toolName string, tp *ToolPolicy, inputSchema map[string]any) error {
	if tp == nil || !tp.Enabled {
		return nil
	}
	checkPath := func(path string, expectedTypes []string) error {
		leafType, err := resolvePathInSchema(inputSchema, strings.Split(path, "."))
		if err != nil {
			return NewError(ErrPolicySchemaTypeMismatch, 0, "tool %q policy path %q invalid against inputSchema: %v", toolName, path, err)
		}
		if !slices.Contains(expectedTypes, leafType) {
			return NewError(ErrPolicySchemaTypeMismatch, 0, "tool %q policy path %q has schema type %q, expected %v", toolName, path, leafType, expectedTypes)
		}
		return nil
	}

	if tp.PrimaryTargetPath != "" {
		if err := checkPath(tp.PrimaryTargetPath, []string{"string"}); err != nil {
			return err
		}
	}
	for _, b := range tp.SubjectTargetBindings {
		if err := checkPath(b.Path, []string{"string"}); err != nil {
			return err
		}
	}
	for _, b := range tp.ProtectedTargetBindings {
		if err := checkPath(b.Path, []string{"string"}); err != nil {
			return err
		}
	}
	if tp.SoDBinding != nil {
		if err := checkPath(tp.SoDBinding.SubjectPath, []string{"string"}); err != nil {
			return err
		}
		if err := checkPath(tp.SoDBinding.EntitlementPath, []string{"string"}); err != nil {
			return err
		}
	}
	for _, b := range tp.ArrayCapBindings {
		if err := checkPath(b.Path, []string{"array"}); err != nil {
			return err
		}
	}
	for _, b := range tp.LimitArgBindings {
		if err := checkPath(b.Path, []string{"integer", "number"}); err != nil {
			return err
		}
	}
	return nil
}

func resolvePathInSchema(node map[string]any, segments []string) (string, error) {
	if len(segments) == 0 {
		return parseAllowedSchemaType(node["type"], false, "")
	}
	seg := segments[0]
	isWildcard := strings.HasSuffix(seg, "[*]")
	fieldName := strings.TrimSuffix(seg, "[*]")

	props, ok := node["properties"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("schema node has no properties for segment %q", seg)
	}
	propNode, ok := props[fieldName].(map[string]any)
	if !ok {
		return "", fmt.Errorf("property %q not declared in inputSchema", fieldName)
	}
	propType, err := parseAllowedSchemaType(propNode["type"], false, fieldName)
	if err != nil {
		return "", err
	}
	if isWildcard {
		if propType != "array" {
			return "", fmt.Errorf("property %q uses [*] but schema type is %q", fieldName, propType)
		}
		itemsNode, ok := propNode["items"].(map[string]any)
		if !ok {
			return "", fmt.Errorf("array property %q missing items schema", fieldName)
		}
		return resolvePathInSchema(itemsNode, segments[1:])
	}
	return resolvePathInSchema(propNode, segments[1:])
}

// CompileJSONSchema compiles a raw schema map using github.com/google/jsonschema-go/jsonschema.
func CompileJSONSchema(schemaMap map[string]any) (*jsonschema.Resolved, error) {
	raw, err := json.Marshal(schemaMap)
	if err != nil {
		return nil, err
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: false})
}
