//go:build unix

package authz

import "fmt"

// ErrorCode enumerates all normative startup, CLI, and runtime error codes
// defined in SPEC-AUTHZ-01 §7.
type ErrorCode string

const (
	// §7.1 Startup / CLI Exit Codes
	ErrTCBInvalidPath                 ErrorCode = "TCB_INVALID_PATH"
	ErrTCBSymlinkForbidden            ErrorCode = "TCB_SYMLINK_FORBIDDEN"
	ErrTCBOwnerMismatch               ErrorCode = "TCB_OWNER_MISMATCH"
	ErrTCBPermissionsTooOpen          ErrorCode = "TCB_PERMISSIONS_TOO_OPEN"
	ErrTCBFilesystemUnsupported       ErrorCode = "TCB_FILESYSTEM_UNSUPPORTED"
	ErrTCBUIDBoundaryRequired         ErrorCode = "TCB_UID_BOUNDARY_REQUIRED"
	ErrModeAWriteForbidden            ErrorCode = "MODE_A_WRITE_FORBIDDEN"
	ErrTestFlagForbiddenInProd        ErrorCode = "TEST_FLAG_FORBIDDEN_IN_PROD"
	ErrStateLedgerUninitialized       ErrorCode = "STATE_LEDGER_UNINITIALIZED"
	ErrAuditLogUninitialized          ErrorCode = "AUDIT_LOG_UNINITIALIZED"
	ErrPolicySignatureInvalid         ErrorCode = "POLICY_SIGNATURE_INVALID"
	ErrWriteToolRequiresJWT           ErrorCode = "WRITE_TOOL_REQUIRES_JWT"
	ErrPerCallJWTForbidden            ErrorCode = "PER_CALL_JWT_FORBIDDEN"
	ErrWildcardScopeForbidden         ErrorCode = "WILDCARD_SCOPE_FORBIDDEN"
	ErrKeyReuseForbidden              ErrorCode = "KEY_REUSE_FORBIDDEN"
	ErrKnownTestKeyForbidden          ErrorCode = "KNOWN_TEST_KEY_FORBIDDEN"
	ErrForbiddenPassEnv               ErrorCode = "FORBIDDEN_PASS_ENV"
	ErrInvalidSecretEnvValue          ErrorCode = "INVALID_SECRET_ENV_VALUE"
	ErrMissingSelfTargetPolicy        ErrorCode = "MISSING_SELF_TARGET_POLICY"
	ErrZeroWriteBudgetOnWriteTool     ErrorCode = "ZERO_WRITE_BUDGET_ON_WRITE_TOOL"
	ErrPolicyIdentifierNonCanonical   ErrorCode = "POLICY_IDENTIFIER_NONCANONICAL"
	ErrUpstreamScriptForbidden        ErrorCode = "UPSTREAM_SCRIPT_INTERPRETER_FORBIDDEN"
	ErrUpstreamSchemaUnsupported      ErrorCode = "UPSTREAM_SCHEMA_UNSUPPORTED"
	ErrUpstreamSchemaDefaultForbidden ErrorCode = "UPSTREAM_SCHEMA_DEFAULT_FORBIDDEN"
	ErrReservedArgumentCollision      ErrorCode = "RESERVED_ARGUMENT_COLLISION"
	ErrPolicySchemaTypeMismatch       ErrorCode = "POLICY_SCHEMA_TYPE_MISMATCH"
	ErrReadClassAnnotationMismatch    ErrorCode = "READ_CLASS_ANNOTATION_MISMATCH"
	ErrManifestPinMismatch            ErrorCode = "MANIFEST_PIN_MISMATCH"
	ErrAuditLogCorrupted              ErrorCode = "AUDIT_LOG_CORRUPTED"
	ErrIntentPreimageMismatch         ErrorCode = "INTENT_PREIMAGE_MISMATCH"

	// §7.3 Stage 0: Availability & Epoch
	ErrManifestRugPullDetected   ErrorCode = "MANIFEST_RUG_PULL_DETECTED"
	ErrUpstreamProcessTerminated ErrorCode = "UPSTREAM_PROCESS_TERMINATED"
	ErrToolNotEnabled            ErrorCode = "TOOL_NOT_ENABLED"

	// §7.3 Stage 1: JSON & Schema
	ErrPayloadTooLarge          ErrorCode = "PAYLOAD_TOO_LARGE"
	ErrMaxJSONDepthExceeded     ErrorCode = "MAX_JSON_DEPTH_EXCEEDED"
	ErrDuplicateJSONKey         ErrorCode = "DUPLICATE_JSON_KEY"
	ErrCaseCollidingJSONKey     ErrorCode = "CASE_COLLIDING_JSON_KEY"
	ErrJSONIntegerPrecisionLoss ErrorCode = "JSON_INTEGER_PRECISION_LOSS"
	ErrInvalidJSONNumber        ErrorCode = "INVALID_JSON_NUMBER"
	ErrInvalidControlChar       ErrorCode = "INVALID_CONTROL_CHAR"
	ErrUnknownToolArgument      ErrorCode = "UNKNOWN_TOOL_ARGUMENT"
	ErrSchemaValidationFailed   ErrorCode = "SCHEMA_VALIDATION_FAILED"

	// §7.3 Stage 2: Principal & OBO
	ErrPrincipalJWTMissing              ErrorCode = "PRINCIPAL_JWT_MISSING"
	ErrPrincipalTokenOverrideForbidden  ErrorCode = "PRINCIPAL_TOKEN_OVERRIDE_FORBIDDEN"
	ErrPrincipalJWTExpiredOrInvalid     ErrorCode = "PRINCIPAL_JWT_EXPIRED_OR_INVALID"
	ErrPrincipalGroupOverageUnsupported ErrorCode = "PRINCIPAL_GROUP_OVERAGE_UNSUPPORTED"
	ErrOBOScopeDenied                   ErrorCode = "OBO_SCOPE_DENIED"

	// §7.3 Stage 3: Guardrails & SoD
	ErrRequiredTargetArgMissing   ErrorCode = "REQUIRED_TARGET_ARG_MISSING"
	ErrArgumentTypeInvalid        ErrorCode = "ARGUMENT_TYPE_INVALID"
	ErrInvalidIdentifierChars     ErrorCode = "INVALID_IDENTIFIER_CHARS"
	ErrNonCanonicalIdentifier     ErrorCode = "NON_CANONICAL_IDENTIFIER"
	ErrTier0ProtectedTarget       ErrorCode = "TIER0_PROTECTED_TARGET"
	ErrSelfDealingClaimMissing    ErrorCode = "SELF_DEALING_CLAIM_MISSING"
	ErrSelfDealingForbidden       ErrorCode = "SELF_DEALING_FORBIDDEN"
	ErrSoDConflictDetected        ErrorCode = "SOD_CONFLICT_DETECTED"
	ErrBlastRadiusArrayCap        ErrorCode = "BLAST_RADIUS_ARRAY_CAP_EXCEEDED"
	ErrBlastRadiusLimitExceeded   ErrorCode = "BLAST_RADIUS_LIMIT_EXCEEDED"
	ErrArgumentConstraintViolated ErrorCode = "ARGUMENT_CONSTRAINT_VIOLATION"

	// §7.3 Stage 4: Step-Up & Commit
	ErrChallengeRateLimitExceeded      ErrorCode = "CHALLENGE_RATE_LIMIT_EXCEEDED"
	ErrStepUpApprovalRequired          ErrorCode = "STEP_UP_APPROVAL_REQUIRED"
	ErrAmbiguousApprovalToken          ErrorCode = "AMBIGUOUS_APPROVAL_TOKEN"
	ErrApproverNotAuthorized           ErrorCode = "APPROVER_NOT_AUTHORIZED"
	ErrApprovalSignatureInvalid        ErrorCode = "APPROVAL_SIGNATURE_INVALID"
	ErrApprovalNonInteractiveForbidden ErrorCode = "APPROVAL_NON_INTERACTIVE_FORBIDDEN"
	ErrApprovalTokenExpired            ErrorCode = "APPROVAL_TOKEN_EXPIRED"
	ErrApprovalIntentMismatch          ErrorCode = "APPROVAL_INTENT_MISMATCH"
	ErrSelfApprovalForbidden           ErrorCode = "SELF_APPROVAL_FORBIDDEN"
	ErrPrincipalWriteBudgetExhausted   ErrorCode = "PRINCIPAL_WRITE_BUDGET_EXHAUSTED"
	ErrApprovalTokenReplayed           ErrorCode = "APPROVAL_TOKEN_REPLAYED"
	ErrStateLedgerUnavailable          ErrorCode = "STATE_LEDGER_UNAVAILABLE"
	ErrAuditLogUnavailable             ErrorCode = "AUDIT_LOG_UNAVAILABLE"

	// §7.3 Post-Forward: Output
	ErrUpstreamCallTimeout         ErrorCode = "UPSTREAM_CALL_TIMEOUT"
	ErrUpstreamCallCancelled       ErrorCode = "UPSTREAM_CALL_CANCELLED"
	ErrUpstreamOutputTooLarge      ErrorCode = "UPSTREAM_OUTPUT_TOO_LARGE"
	ErrUpstreamOutputResource      ErrorCode = "UPSTREAM_OUTPUT_RESOURCE_FORBIDDEN"
	ErrUpstreamOutputSchemaViol    ErrorCode = "UPSTREAM_OUTPUT_SCHEMA_VIOLATION"
	ErrUpstreamOutputSecretLeak    ErrorCode = "UPSTREAM_OUTPUT_SECRET_DETECTED"
)

// AuthzError carries a deterministic ErrorCode, stage number, and message.
type AuthzError struct {
	Code    ErrorCode
	Stage   int
	Message string
}

func (e *AuthzError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewError(code ErrorCode, stage int, format string, args ...any) *AuthzError {
	return &AuthzError{
		Code:    code,
		Stage:   stage,
		Message: fmt.Sprintf(format, args...),
	}
}

// RejectionReceiptV1 is the structured JSON receipt returned in CallToolResult.Content[0]
// whenever a tool call is denied.
type RejectionReceiptV1 struct {
	Status     string    `json:"status"`
	Stage      int       `json:"stage"`
	ErrorCode  ErrorCode `json:"error_code"`
	ServerName string    `json:"server_name"`
	ToolName   string    `json:"tool_name"`
	Reason     string    `json:"reason"`
}
