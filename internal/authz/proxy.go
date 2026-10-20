//go:build unix

package authz

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Gateway is the deterministic 5-stage Policy Enforcement Point (PEP) mediating between
// an MCP Host and an upstream MCP server.
type Gateway struct {
	pol           *PolicyV1
	lockfile      *ManifestLockfileV1
	ledger        *Ledger
	upstream      *UpstreamHandle
	secretScanner *SecretScanner
	startupJWT    string

	compiledInputSchemas  map[string]*jsonschema.Resolved
	compiledOutputSchemas map[string]*jsonschema.Resolved

	// Generation-counter epoch synchronization (§4.1.2):
	// Lock acquisition order is strictly: epochMu -> ledger.ledgerMu -> flock(lockFd).
	epochMu      sync.RWMutex
	notifiedGen  atomic.Uint64
	verifiedGen  atomic.Uint64
	poisoned     atomic.Bool
	upstreamDead atomic.Bool

	nowFunc func() time.Time
}

// GatewayOptions configures Gateway initialization.
type GatewayOptions struct {
	Policy         *PolicyV1
	Lockfile       *ManifestLockfileV1
	Ledger         *Ledger
	Upstream       *UpstreamHandle
	SubjectJWT     string
	SecretValues   map[string]string
	NowFunc        func() time.Time
}

// NewGateway initializes a Gateway after verifying the initial upstream tool manifest against lockfile.
func NewGateway(ctx context.Context, opts GatewayOptions) (*Gateway, error) {
	if opts.Policy == nil || opts.Lockfile == nil || opts.Ledger == nil || opts.Upstream == nil {
		return nil, NewError(ErrManifestPinMismatch, 0, "Policy, Lockfile, Ledger, and Upstream are required")
	}
	nowFn := opts.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}

	var extraSecrets []string
	if strings.TrimSpace(opts.SubjectJWT) != "" {
		extraSecrets = append(extraSecrets, opts.SubjectJWT)
	}
	secretMap := opts.SecretValues
	if secretMap == nil && opts.Upstream != nil {
		secretMap = opts.Upstream.SecretValues
	}

	gw := &Gateway{
		pol:                   opts.Policy,
		lockfile:              opts.Lockfile,
		ledger:                opts.Ledger,
		upstream:              opts.Upstream,
		secretScanner:         NewSecretScanner(secretMap, extraSecrets...),
		startupJWT:            strings.TrimSpace(opts.SubjectJWT),
		compiledInputSchemas:  make(map[string]*jsonschema.Resolved),
		compiledOutputSchemas: make(map[string]*jsonschema.Resolved),
		nowFunc:               nowFn,
	}
	gw.notifiedGen.Store(1)

	// Compile input and output JSON schemas for all pinned tools
	for tName, pinned := range gw.lockfile.Tools {
		inRes, err := CompileJSONSchema(pinned.InputSchema)
		if err != nil {
			return nil, NewError(ErrUpstreamSchemaUnsupported, 0, "compile inputSchema for %q: %v", tName, err)
		}
		gw.compiledInputSchemas[tName] = inRes
		if pinned.OutputSchema != nil {
			outRes, err := CompileJSONSchema(pinned.OutputSchema)
			if err != nil {
				return nil, NewError(ErrUpstreamSchemaUnsupported, 0, "compile outputSchema for %q: %v", tName, err)
			}
			gw.compiledOutputSchemas[tName] = outRes
		}
	}

	// Verify startup JWT immediately if require_jwt is true and allow_per_call_jwt is false
	requireJWT := gw.pol.PrincipalAuth.RequireJWT != nil && *gw.pol.PrincipalAuth.RequireJWT
	if requireJWT && !gw.pol.PrincipalAuth.AllowPerCallJWT {
		if _, err := gw.resolvePrincipal(nil); err != nil {
			return nil, err
		}
	}

	// Initial startup manifest verification against lockfile
	liveTools, _, err := FetchAndCanonicalizeUpstreamTools(ctx, gw.upstream.Session, false)
	if err != nil {
		return nil, err
	}
	if err := VerifyManifestAgainstLockfile(gw.pol, gw.lockfile, liveTools, false); err != nil {
		return nil, err
	}
	gw.verifiedGen.Store(1)

	// Record startup audit event
	_ = gw.ledger.AppendAudit(AuditRecordV1{
		Timestamp:       gw.nowFunc().UTC().Format(time.RFC3339Nano),
		ToolName:        "_system",
		ActionClass:     "system",
		Decision:        "gateway_started",
		Stage:           0,
		PrincipalID:     "_system",
		PrincipalSub:    "_system",
		EffectiveScopes: []string{},
		RedactedArgs:    map[string]any{},
	}, gw.nowFunc())

	return gw, nil
}

// OnToolListChanged is the non-blocking callback registered on the upstream mcp.Client (§4.1.2):
// increments notifiedGen atomically without acquiring any mutex on the client read loop.
func (gw *Gateway) OnToolListChanged(_ context.Context, _ *mcp.ToolListChangedRequest) {
	gw.notifiedGen.Add(1)
}

// OnUpstreamProcessExit marks the upstream subprocess as terminated.
func (gw *Gateway) OnUpstreamProcessExit() {
	gw.upstreamDead.Store(true)
}

// Close closes the upstream session and state ledger.
func (gw *Gateway) Close() {
	if gw.upstream != nil {
		gw.upstream.Close()
	}
	if gw.ledger != nil {
		_ = gw.ledger.Close()
	}
}

// NewHostServer creates the host-facing `mcp.Server` with `Capabilities: Tools{ListChanged: false}`
// (suppressing default `logging` capability advertisement) and installs the default-deny receiving middleware (§4.7.1).
func (gw *Gateway) NewHostServer() *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: gw.pol.ServerName, Version: "0.1.0"},
		&mcp.ServerOptions{
			Capabilities: &mcp.ServerCapabilities{
				Tools: &mcp.ToolCapabilities{ListChanged: false},
			},
		},
	)
	server.AddReceivingMiddleware(gw.receivingMiddleware)
	return server
}

func (gw *Gateway) receivingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "initialize", "notifications/initialized", "ping", "notifications/cancelled":
			return next(ctx, method, req)

		case "tools/list":
			return gw.HandleToolsList(ctx)

		case "tools/call":
			var toolName string
			var rawArgs []byte
			var reqMeta map[string]any
			if params := req.GetParams(); params != nil {
				switch p := params.(type) {
				case *mcp.CallToolParamsRaw:
					toolName = p.Name
					rawArgs = p.Arguments
					reqMeta = p.Meta
				case *mcp.CallToolParams:
					toolName = p.Name
					reqMeta = p.Meta
					if p.Arguments != nil {
						rawArgs, _ = json.Marshal(p.Arguments)
					}
				}
			}
			return gw.EvaluateToolCall(ctx, toolName, rawArgs, reqMeta), nil

		default:
			_ = gw.ledger.AppendAudit(AuditRecordV1{
				Timestamp:       gw.nowFunc().UTC().Format(time.RFC3339Nano),
				ToolName:        method,
				ActionClass:     "protocol",
				Decision:        "deny",
				Stage:           0,
				ErrorCode:       "METHOD_NOT_ALLOWED",
				PrincipalID:     "_protocol",
				PrincipalSub:    "_protocol",
				EffectiveScopes: []string{},
				RedactedArgs:    map[string]any{"method": method},
			}, gw.nowFunc())
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.CodeMethodNotFound,
				Message: "mcp-authz-gateway: METHOD_NOT_ALLOWED",
			}
		}
	}
}

// HandleToolsList serves `tools/list` from the verified lockfile, filtering unauthorized tools
// when `hide_unauthorized_tools: true` and injecting `__mcp_authz_approval_token` into `write:high-risk` schemas.
func (gw *Gateway) HandleToolsList(ctx context.Context) (*mcp.ListToolsResult, error) {
	if gw.poisoned.Load() {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: string(ErrManifestRugPullDetected)}
	}
	if gw.upstreamDead.Load() {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: string(ErrUpstreamProcessTerminated)}
	}
	if gw.notifiedGen.Load() != gw.verifiedGen.Load() {
		gw.epochMu.Lock()
		err := gw.reverifyManifestLocked(ctx)
		gw.epochMu.Unlock()
		if err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: err.Error()}
		}
	}

	var pctx *PrincipalContext
	if gw.pol.AgentProfile.HideUnauthorizedTools {
		var err error
		pctx, err = gw.resolvePrincipal(nil)
		if err != nil {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{}}, nil
		}
	}

	toolNames := make([]string, 0, len(gw.lockfile.Tools))
	for name := range gw.lockfile.Tools {
		toolNames = append(toolNames, name)
	}
	slices.Sort(toolNames)

	tools := make([]*mcp.Tool, 0, len(toolNames))
	for _, name := range toolNames {
		tp := gw.pol.Tools[name]
		if tp == nil || !tp.Enabled {
			continue
		}
		if gw.pol.AgentProfile.HideUnauthorizedTools && pctx != nil {
			if err := AuthorizeToolOBO(pctx, tp.RequiredScopes); err != nil {
				continue
			}
		}
		pinned := gw.lockfile.Tools[name]
		tools = append(tools, buildHostToolDescriptor(pinned, tp.ActionClass == "write:high-risk"))
	}
	return &mcp.ListToolsResult{Tools: tools}, nil
}

func buildHostToolDescriptor(pinned *PinnedToolEntryV1, isHighRisk bool) *mcp.Tool {
	inClone := deepCloneMap(pinned.InputSchema)
	if isHighRisk {
		props, _ := inClone["properties"].(map[string]any)
		if props == nil {
			props = make(map[string]any)
			inClone["properties"] = props
		}
		props[ApprovalTokenArgName] = map[string]any{
			"type":        "string",
			"description": "Ed25519 step-up approval token (mcp_appr_v1.<payload>.<sig>)",
		}
	}
	var outClone any
	if pinned.OutputSchema != nil {
		outClone = deepCloneMap(pinned.OutputSchema)
	}
	destHint := pinned.DestructiveHint
	openHint := pinned.OpenWorldHint
	return &mcp.Tool{
		Name:         pinned.Name,
		Title:        pinned.Title,
		Description:  pinned.Description,
		InputSchema:  inClone,
		OutputSchema: outClone,
		Annotations: &mcp.ToolAnnotations{
			Title:           pinned.Title,
			ReadOnlyHint:    pinned.ReadOnlyHint,
			DestructiveHint: &destHint,
			IdempotentHint:  pinned.IdempotentHint,
			OpenWorldHint:   &openHint,
		},
	}
}

func deepCloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// reverifyManifestLocked Must be called with `gw.epochMu.Lock()` held!
// Snapshots `g := gw.notifiedGen.Load()`, fetches live tools (bypassing go-sdk toolsCache via
// sending middleware TTLMs=0), verifies against `gw.lockfile`, and stores `gw.verifiedGen.Store(g)`.
func (gw *Gateway) reverifyManifestLocked(ctx context.Context) error {
	if gw.poisoned.Load() {
		return NewError(ErrManifestRugPullDetected, 0, "gateway is permanently poisoned after manifest rug-pull detection")
	}
	if gw.upstreamDead.Load() {
		return NewError(ErrUpstreamProcessTerminated, 0, "upstream process is terminated")
	}

	g := gw.notifiedGen.Load()
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(gw.pol.Upstream.CallTimeoutMs)*time.Millisecond)
	defer cancel()

	liveTools, _, err := FetchAndCanonicalizeUpstreamTools(timeoutCtx, gw.upstream.Session, true)
	if err != nil {
		var ae *AuthzError
		if asAuthzError(err, &ae) && ae.Code == ErrUpstreamProcessTerminated {
			gw.upstreamDead.Store(true)
			return ae
		}
		gw.poisonUpstreamLocked(err.Error())
		return NewError(ErrManifestRugPullDetected, 0, "manifest re-verification failed: %v", err)
	}

	if err := VerifyManifestAgainstLockfile(gw.pol, gw.lockfile, liveTools, true); err != nil {
		gw.poisonUpstreamLocked(err.Error())
		return err
	}

	gw.verifiedGen.Store(g)
	return nil
}

func (gw *Gateway) poisonUpstreamLocked(reason string) {
	gw.poisoned.Store(true)
	if gw.upstream != nil {
		gw.upstream.Close()
	}
	safeReason := reason
	if gw.secretScanner != nil {
		safeReason = gw.secretScanner.RedactString(reason)
	}
	_ = gw.ledger.AppendAudit(AuditRecordV1{
		Timestamp:       gw.nowFunc().UTC().Format(time.RFC3339Nano),
		ToolName:        "_manifest_reverify",
		ActionClass:     "system",
		Decision:        "abort",
		Stage:           0,
		ErrorCode:       string(ErrManifestRugPullDetected),
		PrincipalID:     "_system",
		PrincipalSub:    "_system",
		EffectiveScopes: []string{},
		RedactedArgs:    map[string]any{"reason": safeReason},
	}, gw.nowFunc())
}

func (gw *Gateway) resolvePrincipal(reqMeta map[string]any) (*PrincipalContext, error) {
	now := gw.nowFunc()
	requireJWT := gw.pol.PrincipalAuth.RequireJWT != nil && *gw.pol.PrincipalAuth.RequireJWT
	if !requireJWT {
		pctx := &PrincipalContext{
			Anonymous:   true,
			Sub:         "anonymous",
			IdentityID:  "anonymous",
			Email:       "",
			TokenDigest: "",
			Claims:      map[string]any{},
		}
		if err := PopulateOBOScopes(pctx, &gw.pol.PrincipalAuth, &gw.pol.AgentProfile); err != nil {
			return nil, err
		}
		return pctx, nil
	}

	var metaJWT string
	var hasMetaJWT bool
	if reqMeta != nil {
		if raw, exists := reqMeta["io.identity-mcp/subject_jwt"]; exists {
			hasMetaJWT = true
			if s, ok := raw.(string); ok {
				metaJWT = strings.TrimSpace(s)
			}
		}
	}

	if hasMetaJWT && !gw.pol.PrincipalAuth.AllowPerCallJWT {
		return nil, NewError(ErrPrincipalTokenOverrideForbidden, 2, "per-call _meta[\"io.identity-mcp/subject_jwt\"] is forbidden when allow_per_call_jwt is false")
	}

	rawJWT := gw.startupJWT
	if gw.pol.PrincipalAuth.AllowPerCallJWT && hasMetaJWT {
		rawJWT = metaJWT
	}
	if rawJWT == "" {
		return nil, NewError(ErrPrincipalJWTMissing, 2, "missing principal JWT")
	}

	pctx, err := VerifyPrincipalJWT(rawJWT, &gw.pol.PrincipalAuth, gw.pol.ParsedVerifierKeys, gw.pol.CompiledIdentityRegex, now)
	if err != nil {
		return nil, err
	}
	if err := PopulateOBOScopes(pctx, &gw.pol.PrincipalAuth, &gw.pol.AgentProfile); err != nil {
		return nil, err
	}
	return pctx, nil
}

// EvaluateToolCall executes the normative 5-stage PEP evaluation pipeline for a `tools/call` invocation.
func (gw *Gateway) EvaluateToolCall(ctx context.Context, toolName string, rawArgs []byte, reqMeta map[string]any) *mcp.CallToolResult {
	now := gw.nowFunc()
	tp := gw.pol.Tools[toolName]
	actionClass := "unknown"
	var redactPaths []string
	if tp != nil {
		actionClass = tp.ActionClass
		redactPaths = tp.RedactArgs
	}

	// Stage 0: Poison / Upstream liveness / Dirty Manifest Check / Tool Enablement
	if gw.poisoned.Load() {
		return gw.denyAndAudit(toolName, actionClass, 0, ErrManifestRugPullDetected, "gateway poisoned due to upstream manifest drift", nil, nil, redactPaths, now)
	}
	if gw.upstreamDead.Load() {
		return gw.denyAndAudit(toolName, actionClass, 0, ErrUpstreamProcessTerminated, "upstream process is terminated", nil, nil, redactPaths, now)
	}
	if gw.notifiedGen.Load() != gw.verifiedGen.Load() {
		gw.epochMu.Lock()
		reverifyErr := gw.reverifyManifestLocked(ctx)
		gw.epochMu.Unlock()
		if reverifyErr != nil {
			return gw.denyFromError(toolName, actionClass, 0, reverifyErr, nil, nil, redactPaths, now)
		}
	}

	pinned := gw.lockfile.Tools[toolName]
	if tp == nil || !tp.Enabled || pinned == nil {
		return gw.denyAndAudit(toolName, actionClass, 0, ErrToolNotEnabled, "tool is not enabled in policy.json", nil, nil, redactPaths, now)
	}

	// Stage 1: Strict JSON Decode, Token Extraction, Limit Defaults, Unknown Key & Schema Validation
	cleanArgs, err := DecodeStrictJSONObject(rawArgs, true)
	if err != nil {
		return gw.denyFromError(toolName, actionClass, 1, err, nil, nil, redactPaths, now)
	}

	approvalToken, err := ExtractAndStripApprovalToken(cleanArgs, reqMeta, tp.ActionClass == "write:high-risk")
	if err != nil {
		return gw.denyFromError(toolName, actionClass, 4, err, nil, cleanArgs, redactPaths, now)
	}

	InjectLimitDefaults(cleanArgs, tp.LimitArgBindings)

	if err := CheckUnknownToolArguments(cleanArgs, pinned.InputSchema); err != nil {
		return gw.denyFromError(toolName, actionClass, 1, err, nil, cleanArgs, redactPaths, now)
	}

	if resolvedSchema := gw.compiledInputSchemas[toolName]; resolvedSchema != nil {
		if err := resolvedSchema.Validate(cleanArgs); err != nil {
			return gw.denyAndAudit(toolName, actionClass, 1, ErrSchemaValidationFailed, "arguments failed JSON Schema validation: "+err.Error(), nil, cleanArgs, redactPaths, now)
		}
	}

	// Stage 2: Principal Authentication & OBO Scope Intersection
	pctx, err := gw.resolvePrincipal(reqMeta)
	if err != nil {
		return gw.denyFromError(toolName, actionClass, 2, err, pctx, cleanArgs, redactPaths, now)
	}
	if err := AuthorizeToolOBO(pctx, tp.RequiredScopes); err != nil {
		return gw.denyFromError(toolName, actionClass, 2, err, pctx, cleanArgs, redactPaths, now)
	}

	// Stage 3: Canonical Identifier Guardrails, Tier-0 Denylist, Self-Dealing, SoD, Caps & Constraints
	ledgerID, activeGrants, err := gw.ledger.ActiveGrantsSnapshot()
	if err != nil {
		return gw.denyFromError(toolName, actionClass, 4, err, pctx, cleanArgs, redactPaths, now)
	}
	targetCount, sodSubjects, sodEntitlements, err := EvaluateStage3Guardrails(gw.pol, tp, cleanArgs, pctx, activeGrants)
	if err != nil {
		return gw.denyFromError(toolName, actionClass, 3, err, pctx, cleanArgs, redactPaths, now)
	}

	// Stage 4 & Upstream Forwarding
	if tp.ActionClass == "read" {
		return gw.executeReadCall(ctx, toolName, tp, pctx, cleanArgs, now)
	}
	return gw.executeWriteCall(ctx, toolName, tp, ledgerID, pctx, cleanArgs, approvalToken, targetCount, sodSubjects, sodEntitlements, now)
}

func (gw *Gateway) executeReadCall(
	ctx context.Context,
	toolName string,
	tp *ToolPolicy,
	pctx *PrincipalContext,
	cleanArgs map[string]any,
	now time.Time,
) *mcp.CallToolResult {
	for {
		gw.epochMu.RLock()
		if gw.poisoned.Load() {
			gw.epochMu.RUnlock()
			return gw.denyAndAudit(toolName, tp.ActionClass, 0, ErrManifestRugPullDetected, "gateway poisoned", pctx, cleanArgs, tp.RedactArgs, now)
		}
		if gw.upstreamDead.Load() {
			gw.epochMu.RUnlock()
			return gw.denyAndAudit(toolName, tp.ActionClass, 0, ErrUpstreamProcessTerminated, "upstream terminated", pctx, cleanArgs, tp.RedactArgs, now)
		}
		if gw.notifiedGen.Load() == gw.verifiedGen.Load() {
			break
		}
		gw.epochMu.RUnlock()

		gw.epochMu.Lock()
		reverifyErr := gw.reverifyManifestLocked(ctx)
		gw.epochMu.Unlock()
		if reverifyErr != nil {
			return gw.denyFromError(toolName, tp.ActionClass, 0, reverifyErr, pctx, cleanArgs, tp.RedactArgs, now)
		}
	}

	startTime := time.Now()
	upRes, upErr := gw.callUpstreamSession(ctx, toolName, cleanArgs)
	durationMs := time.Since(startTime).Milliseconds()
	gw.epochMu.RUnlock()

	sanitizedRes, decision, stage, errCode := gw.sanitizeUpstreamResult(toolName, upRes, upErr)
	auditRec := gw.buildBaseAuditRecord(toolName, tp.ActionClass, decision, stage, errCode, pctx, cleanArgs, tp.RedactArgs, now)
	auditRec.UpstreamDurationMs = durationMs
	auditRec.UpstreamIsError = sanitizedRes.IsError

	if err := gw.ledger.AppendAudit(auditRec, gw.nowFunc()); err != nil {
		return makeRejectionResult(gw.pol.ServerName, toolName, 4, ErrAuditLogUnavailable, "audit log write failed")
	}
	return sanitizedRes
}

func (gw *Gateway) executeWriteCall(
	ctx context.Context,
	toolName string,
	tp *ToolPolicy,
	ledgerID string,
	pctx *PrincipalContext,
	cleanArgs map[string]any,
	approvalToken string,
	targetCount int,
	sodSubjects []string,
	sodEntitlements []string,
	now time.Time,
) *mcp.CallToolResult {
	var approvalClaims *ApprovalTokenClaimsV1
	var intentDigest string

	if tp.ActionClass == "write:high-risk" {
		intent, digest, err := BuildIntentPayload(gw.pol, gw.lockfile, ledgerID, toolName, tp, pctx, cleanArgs)
		if err != nil {
			return gw.denyAndAudit(toolName, tp.ActionClass, 4, ErrStateLedgerUnavailable, err.Error(), pctx, cleanArgs, tp.RedactArgs, now)
		}
		intentDigest = digest

		if strings.TrimSpace(approvalToken) == "" {
			chAudit := gw.buildBaseAuditRecord(toolName, tp.ActionClass, "challenge", 4, ErrStepUpApprovalRequired, pctx, cleanArgs, tp.RedactArgs, now)
			chAudit.IntentDigest = intentDigest
			if err := gw.ledger.RecordChallengeAndAudit(pctx.IdentityID, chAudit, now); err != nil {
				var ae *AuthzError
				if asAuthzError(err, &ae) {
					return makeRejectionResult(gw.pol.ServerName, toolName, ae.Stage, ae.Code, ae.Message)
				}
				return makeRejectionResult(gw.pol.ServerName, toolName, 4, ErrStateLedgerUnavailable, err.Error())
			}
			receipt, _, err := WriteChallengeReceipt(gw.pol, intent, intentDigest)
			if err != nil {
				return gw.denyFromError(toolName, tp.ActionClass, 4, err, pctx, cleanArgs, tp.RedactArgs, now)
			}
			jcsReceipt, _ := MarshalJCS(receipt)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: string(jcsReceipt)}},
			}
		}

		verifiedClaims, err := VerifyApprovalToken(approvalToken, gw.pol, ledgerID, intentDigest, pctx, now)
		if err != nil {
			return gw.denyFromError(toolName, tp.ActionClass, 4, err, pctx, cleanArgs, tp.RedactArgs, now)
		}
		approvalClaims = verifiedClaims
	}

	// §4.4.3 3-Phase Write Execution under exclusive `gw.epochMu.Lock()`:
	gw.epochMu.Lock()
	defer gw.epochMu.Unlock()

	// Phase 1: Manifest Re-Verification
	reverifyBeforeWrite := gw.pol.ReverifyManifestBeforeWrite == nil || *gw.pol.ReverifyManifestBeforeWrite
	if reverifyBeforeWrite || gw.notifiedGen.Load() != gw.verifiedGen.Load() {
		if err := gw.reverifyManifestLocked(ctx); err != nil {
			return gw.denyFromError(toolName, tp.ActionClass, 0, err, pctx, cleanArgs, tp.RedactArgs, now)
		}
	}

	// Phase 2: Atomic State Commit + Pre-Forward Audit inside single `ledgerMu` + `flock(lockFd)`
	preAudit := gw.buildBaseAuditRecord(toolName, tp.ActionClass, "pre_forward_allow", 4, "", pctx, cleanArgs, tp.RedactArgs, now)
	preAudit.IntentDigest = intentDigest
	if approvalClaims != nil {
		preAudit.ApproverSub = approvalClaims.ApproverSub
		preAudit.ApprovalJTI = approvalClaims.JTI
		preAudit.TicketID = approvalClaims.TicketID
	}

	if err := gw.ledger.CommitWriteAndPreForwardAudit(
		pctx.IdentityID,
		targetCount,
		sodSubjects,
		sodEntitlements,
		approvalClaims,
		preAudit,
		now,
	); err != nil {
		var ae *AuthzError
		if asAuthzError(err, &ae) {
			return makeRejectionResult(gw.pol.ServerName, toolName, ae.Stage, ae.Code, ae.Message)
		}
		return makeRejectionResult(gw.pol.ServerName, toolName, 4, ErrStateLedgerUnavailable, err.Error())
	}

	// Phase 3: Upstream Forward & Post-Forward Audit
	startTime := time.Now()
	upRes, upErr := gw.callUpstreamSession(ctx, toolName, cleanArgs)
	durationMs := time.Since(startTime).Milliseconds()

	sanitizedRes, decision, stage, errCode := gw.sanitizeUpstreamResult(toolName, upRes, upErr)
	if decision == "allow" {
		decision = "post_forward_result"
	}

	postAudit := gw.buildBaseAuditRecord(toolName, tp.ActionClass, decision, stage, errCode, pctx, cleanArgs, tp.RedactArgs, gw.nowFunc())
	postAudit.IntentDigest = intentDigest
	if approvalClaims != nil {
		postAudit.ApproverSub = approvalClaims.ApproverSub
		postAudit.ApprovalJTI = approvalClaims.JTI
		postAudit.TicketID = approvalClaims.TicketID
	}
	postAudit.UpstreamDurationMs = durationMs
	postAudit.UpstreamIsError = sanitizedRes.IsError

	if err := gw.ledger.AppendAudit(postAudit, gw.nowFunc()); err != nil {
		return makeRejectionResult(gw.pol.ServerName, toolName, 4, ErrAuditLogUnavailable, "post-forward audit log write failed")
	}
	return sanitizedRes
}

func (gw *Gateway) callUpstreamSession(ctx context.Context, toolName string, cleanArgs map[string]any) (*mcp.CallToolResult, error) {
	timeoutMs := gw.pol.Upstream.CallTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 15000
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	res, err := gw.upstream.Session.CallTool(callCtx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: cleanArgs,
	})
	if err != nil {
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, NewError(ErrUpstreamCallTimeout, 5, "upstream call to %q timed out after %dms", toolName, timeoutMs)
		}
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
			return nil, NewError(ErrUpstreamCallCancelled, 5, "upstream call to %q cancelled by caller", toolName)
		}
		if strings.Contains(err.Error(), "line too long") || strings.Contains(err.Error(), "exceeds max") {
			return nil, NewError(ErrUpstreamOutputTooLarge, 5, "upstream response exceeded max_output_bytes")
		}
		gw.upstreamDead.Store(true)
		return nil, NewError(ErrUpstreamProcessTerminated, 0, "upstream call failed: %v", err)
	}
	return res, nil
}

// sanitizeUpstreamResult enforces Control 7 (§4.7.2) output size, content type allowlist,
// outputSchema validation, and secret leak prevention.
func (gw *Gateway) sanitizeUpstreamResult(toolName string, upRes *mcp.CallToolResult, upErr error) (*mcp.CallToolResult, string, int, ErrorCode) {
	if upErr != nil {
		var ae *AuthzError
		if asAuthzError(upErr, &ae) {
			return makeRejectionResult(gw.pol.ServerName, toolName, ae.Stage, ae.Code, ae.Message), "deny", ae.Stage, ae.Code
		}
		return makeRejectionResult(gw.pol.ServerName, toolName, 0, ErrUpstreamProcessTerminated, upErr.Error()), "deny", 0, ErrUpstreamProcessTerminated
	}
	if upRes == nil {
		return makeRejectionResult(gw.pol.ServerName, toolName, 0, ErrUpstreamProcessTerminated, "nil CallToolResult from upstream"), "deny", 0, ErrUpstreamProcessTerminated
	}

	rawBytes, err := json.Marshal(upRes)
	if err != nil || len(rawBytes) > gw.pol.Upstream.MaxOutputBytes {
		return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputTooLarge, "upstream result exceeds max_output_bytes"), "deny", 5, ErrUpstreamOutputTooLarge
	}

	cleanContent := make([]mcp.Content, 0, len(upRes.Content))
	for _, item := range upRes.Content {
		switch c := item.(type) {
		case *mcp.TextContent:
			if gw.secretScanner.ContainsSecret(c.Text) {
				return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSecretLeak, "secret material detected in upstream TextContent"), "deny", 5, ErrUpstreamOutputSecretLeak
			}
			cleanContent = append(cleanContent, &mcp.TextContent{
				Text: c.Text,
			})
		case *mcp.ImageContent:
			if gw.secretScanner.ContainsSecret(string(c.Data)) {
				return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSecretLeak, "secret material detected in upstream ImageContent"), "deny", 5, ErrUpstreamOutputSecretLeak
			}
			cleanContent = append(cleanContent, &mcp.ImageContent{
				Data:     slices.Clone(c.Data),
				MIMEType: c.MIMEType,
			})
		case *mcp.AudioContent:
			if gw.secretScanner.ContainsSecret(string(c.Data)) {
				return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSecretLeak, "secret material detected in upstream AudioContent"), "deny", 5, ErrUpstreamOutputSecretLeak
			}
			cleanContent = append(cleanContent, &mcp.AudioContent{
				Data:     slices.Clone(c.Data),
				MIMEType: c.MIMEType,
			})
		case *mcp.EmbeddedResource, *mcp.ResourceLink:
			return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputResource, "upstream result contains forbidden EmbeddedResource or ResourceLink"), "deny", 5, ErrUpstreamOutputResource
		default:
			return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputResource, "unsupported upstream content type"), "deny", 5, ErrUpstreamOutputResource
		}
	}

	var cleanStructured any
	if !upRes.IsError && upRes.StructuredContent != nil {
		scBytes, err := json.Marshal(upRes.StructuredContent)
		if err != nil {
			return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSchemaViol, "marshal StructuredContent failed"), "deny", 5, ErrUpstreamOutputSchemaViol
		}
		if gw.secretScanner.ContainsSecret(string(scBytes)) {
			return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSecretLeak, "secret material detected in upstream StructuredContent"), "deny", 5, ErrUpstreamOutputSecretLeak
		}
		var scDecoded any
		if err := json.Unmarshal(scBytes, &scDecoded); err != nil {
			return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSchemaViol, "unmarshal StructuredContent failed"), "deny", 5, ErrUpstreamOutputSchemaViol
		}
		if outSchema := gw.compiledOutputSchemas[toolName]; outSchema != nil {
			if err := outSchema.Validate(scDecoded); err != nil {
				return makeRejectionResult(gw.pol.ServerName, toolName, 5, ErrUpstreamOutputSchemaViol, "StructuredContent failed outputSchema validation: "+err.Error()), "deny", 5, ErrUpstreamOutputSchemaViol
			}
		}
		cleanStructured = scDecoded
	}

	return &mcp.CallToolResult{
		Meta:              nil,
		Content:           cleanContent,
		StructuredContent: cleanStructured,
		IsError:           upRes.IsError,
	}, "allow", 4, ""
}

func (gw *Gateway) buildBaseAuditRecord(
	toolName string,
	actionClass string,
	decision string,
	stage int,
	errCode ErrorCode,
	pctx *PrincipalContext,
	cleanArgs map[string]any,
	redactPaths []string,
	now time.Time,
) AuditRecordV1 {
	pID := "unauthenticated"
	pSub := "unauthenticated"
	pEmail := ""
	effScopes := []string{}
	if pctx != nil {
		if pctx.IdentityID != "" {
			pID = pctx.IdentityID
		}
		if pctx.Sub != "" {
			pSub = pctx.Sub
		}
		pEmail = pctx.Email
		for s := range pctx.EffectiveScope {
			effScopes = append(effScopes, s)
		}
		slices.Sort(effScopes)
	}
	return AuditRecordV1{
		Timestamp:       now.UTC().Format(time.RFC3339Nano),
		ToolName:        toolName,
		ActionClass:     actionClass,
		Decision:        decision,
		Stage:           stage,
		ErrorCode:       string(errCode),
		PrincipalID:     pID,
		PrincipalSub:    pSub,
		PrincipalEmail:  pEmail,
		EffectiveScopes: effScopes,
		RedactedArgs:    gw.secretScanner.RedactArgsForAudit(cleanArgs, redactPaths),
	}
}

func (gw *Gateway) denyFromError(
	toolName string,
	actionClass string,
	defaultStage int,
	err error,
	pctx *PrincipalContext,
	cleanArgs map[string]any,
	redactPaths []string,
	now time.Time,
) *mcp.CallToolResult {
	var ae *AuthzError
	if asAuthzError(err, &ae) {
		st := ae.Stage
		if st == 0 {
			st = defaultStage
		}
		return gw.denyAndAudit(toolName, actionClass, st, ae.Code, ae.Message, pctx, cleanArgs, redactPaths, now)
	}
	return gw.denyAndAudit(toolName, actionClass, defaultStage, ErrSchemaValidationFailed, err.Error(), pctx, cleanArgs, redactPaths, now)
}

func (gw *Gateway) denyAndAudit(
	toolName string,
	actionClass string,
	stage int,
	code ErrorCode,
	reason string,
	pctx *PrincipalContext,
	cleanArgs map[string]any,
	redactPaths []string,
	now time.Time,
) *mcp.CallToolResult {
	rec := gw.buildBaseAuditRecord(toolName, actionClass, "deny", stage, code, pctx, cleanArgs, redactPaths, now)
	if err := gw.ledger.AppendAudit(rec, now); err != nil {
		return makeRejectionResult(gw.pol.ServerName, toolName, 4, ErrAuditLogUnavailable, "audit log write failed")
	}
	return makeRejectionResult(gw.pol.ServerName, toolName, stage, code, gw.secretScanner.RedactString(reason))
}

func makeRejectionResult(serverName, toolName string, stage int, code ErrorCode, reason string) *mcp.CallToolResult {
	receipt := RejectionReceiptV1{
		Status:     "DENIED",
		Stage:      stage,
		ErrorCode:  code,
		ServerName: SanitizeSafeJSONString(serverName),
		ToolName:   SanitizeSafeJSONString(toolName),
		Reason:     SanitizeSafeJSONString(reason),
	}
	jcsBytes, _ := MarshalJCS(receipt)
	return &mcp.CallToolResult{
		IsError:           true,
		Content:           []mcp.Content{&mcp.TextContent{Text: string(jcsBytes)}},
		StructuredContent: nil,
	}
}

// ServeStdio runs the full `mcp-authz-gateway serve --policy <path>` lifecycle over `mcp.StdioTransport`.
func ServeStdio(ctx context.Context, policyPath string) error {
	pol, err := LoadAndValidatePolicy(policyPath)
	if err != nil {
		return err
	}
	lockfile, rawLockBytes, err := LoadLockfile(pol.TCB.LockfilePath, AllowedConfigUIDs(pol))
	if err != nil {
		return err
	}
	if err := VerifyPolicyAndLockfileSignature(pol, pol.RawPolicyBytes, rawLockBytes); err != nil {
		return err
	}

	ledger, err := OpenLedger(pol)
	if err != nil {
		return err
	}
	defer ledger.Close()

	subjectJWT := os.Getenv("MCP_AUTHZ_SUBJECT_JWT")
	var extraSecrets []string
	if subjectJWT != "" {
		extraSecrets = append(extraSecrets, subjectJWT)
	}

	var gwRef atomic.Pointer[Gateway]
	upHandle, err := StartUpstreamSubprocess(
		ctx,
		pol,
		lockfile.UpstreamBinarySHA256,
		extraSecrets,
		func(c context.Context, r *mcp.ToolListChangedRequest) {
			if g := gwRef.Load(); g != nil {
				g.OnToolListChanged(c, r)
			}
		},
		func() {
			if g := gwRef.Load(); g != nil {
				g.OnUpstreamProcessExit()
			}
		},
	)
	if err != nil {
		return err
	}
	defer upHandle.Close()

	gw, err := NewGateway(ctx, GatewayOptions{
		Policy:       pol,
		Lockfile:     lockfile,
		Ledger:       ledger,
		Upstream:     upHandle,
		SubjectJWT:   subjectJWT,
		SecretValues: upHandle.SecretValues,
	})
	if err != nil {
		return err
	}
	gwRef.Store(gw)

	hostServer := gw.NewHostServer()
	return hostServer.Run(ctx, &mcp.StdioTransport{})
}
