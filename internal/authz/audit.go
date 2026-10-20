//go:build unix

package authz

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
)

const (
	AuditHashDomain   = "MCP-AUTHZ-AUDIT-V1\x00"
	AuditGenesisZeros = "0000000000000000000000000000000000000000000000000000000000000000"
)

// AuditRecordV1 is the hash-chained JSON Lines audit log record format (§4.6.2).
type AuditRecordV1 struct {
	Seq                uint64         `json:"seq"`
	Timestamp          string         `json:"ts"`
	GatewayID          string         `json:"gateway_id"`
	LedgerID           string         `json:"ledger_id"`
	ServerName         string         `json:"server_name"`
	ToolName           string         `json:"tool_name"`
	ActionClass        string         `json:"action_class"`
	Decision           string         `json:"decision"`
	Stage              int            `json:"stage"`
	ErrorCode          string         `json:"error_code"`
	PrincipalID        string         `json:"principal_id"`
	PrincipalSub       string         `json:"principal_sub"`
	PrincipalEmail     string         `json:"principal_email"`
	EffectiveScopes    []string       `json:"effective_scopes"`
	ApproverSub        string         `json:"approver_sub,omitempty"`
	ApprovalJTI        string         `json:"approval_jti,omitempty"`
	TicketID           string         `json:"ticket_id,omitempty"`
	IntentDigest       string         `json:"intent_digest,omitempty"`
	RedactedArgs       map[string]any `json:"redacted_args"`
	UpstreamDurationMs int64          `json:"upstream_duration_ms"`
	UpstreamIsError    bool           `json:"upstream_is_error"`
	PrevHash           string         `json:"prev_hash"`
	RecordHash         string         `json:"record_hash,omitempty"`
}

// ComputeAuditRecordHash computes `hex(SHA256("MCP-AUTHZ-AUDIT-V1\x00" || JCS(record_without_record_hash)))`.
func ComputeAuditRecordHash(rec AuditRecordV1) (string, error) {
	copyRec := rec
	copyRec.RecordHash = ""
	if copyRec.EffectiveScopes == nil {
		copyRec.EffectiveScopes = []string{}
	}
	if copyRec.RedactedArgs == nil {
		copyRec.RedactedArgs = map[string]any{}
	}
	jcsBytes, err := MarshalJCS(copyRec)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(AuditHashDomain))
	h.Write(jcsBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SecretScanner detects and redacts sensitive values from `secret_env_keys` and `MCP_AUTHZ_SUBJECT_JWT`
// across raw, URL-escaped, and 3-alignment base64/base64url representations.
type SecretScanner struct {
	needles []string
}

// NewSecretScanner constructs a deterministic SecretScanner from secret_env_keys values and optional raw JWTs.
func NewSecretScanner(secretValues map[string]string, extraSecrets ...string) *SecretScanner {
	seen := make(map[string]struct{})
	addNeedle := func(s string) {
		if len(s) < 12 {
			return
		}
		seen[s] = struct{}{}
	}

	addAllVariants := func(raw string) {
		raw = strings.TrimSpace(raw)
		if len(raw) < 16 {
			return
		}
		addNeedle(raw)
		addNeedle(url.QueryEscape(raw))
		addNeedle(url.PathEscape(raw))

		// Generate base64 and base64url variants across all 3 byte-alignment offsets (0, 1, 2)
		// so a secret embedded inside a larger base64 blob is still matched.
		b := []byte(raw)
		for offset := 0; offset < 3; offset++ {
			padded := make([]byte, offset+len(b))
			copy(padded[offset:], b)

			stdEnc := base64.RawStdEncoding.EncodeToString(padded)
			urlEnc := base64.RawURLEncoding.EncodeToString(padded)

			// Skip the first `offset` partial characters (0 -> 0, 1 -> 2, 2 -> 3)
			skipPrefix := 0
			if offset == 1 {
				skipPrefix = 2
			} else if offset == 2 {
				skipPrefix = 3
			}
			// Trim trailing partial triplet characters (len(padded)%3: 1 -> trim 1, 2 -> trim 1)
			trimSuffix := 0
			if rem := len(padded) % 3; rem != 0 {
				trimSuffix = 1
			}
			if len(stdEnc) > skipPrefix+trimSuffix {
				addNeedle(stdEnc[skipPrefix : len(stdEnc)-trimSuffix])
			}
			if len(urlEnc) > skipPrefix+trimSuffix {
				addNeedle(urlEnc[skipPrefix : len(urlEnc)-trimSuffix])
			}
		}
		addNeedle(base64.StdEncoding.EncodeToString(b))
		addNeedle(base64.URLEncoding.EncodeToString(b))
	}

	for _, v := range secretValues {
		addAllVariants(v)
	}
	for _, ex := range extraSecrets {
		addAllVariants(ex)
		// For a 3-part JWT, also add the signature and payload segments if >= 16 chars
		if parts := strings.Split(ex, "."); len(parts) == 3 {
			addAllVariants(parts[1])
			addAllVariants(parts[2])
		}
	}

	needles := make([]string, 0, len(seen))
	for n := range seen {
		needles = append(needles, n)
	}
	// Sort longest first for deterministic greedy redaction
	slices.SortFunc(needles, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	return &SecretScanner{needles: needles}
}

// ContainsSecret returns true if s contains any secret needle or PEM private key header.
func (sc *SecretScanner) ContainsSecret(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "-----BEGIN ") && strings.Contains(s, "PRIVATE KEY-----") {
		return true
	}
	if sc == nil {
		return false
	}
	for _, n := range sc.needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// RedactString replaces all secret needles in s with "[REDACTED]".
func (sc *SecretScanner) RedactString(s string) string {
	if s == "" || sc == nil {
		return s
	}
	out := s
	for _, n := range sc.needles {
		if strings.Contains(out, n) {
			out = strings.ReplaceAll(out, n, "[REDACTED]")
		}
	}
	return out
}

// RedactArgsForAudit deep-clones cleanArgs, replaces policy redact_args paths with "[REDACTED]",
// and scrubs any secret values from string leaves.
func (sc *SecretScanner) RedactArgsForAudit(cleanArgs map[string]any, redactPaths []string) map[string]any {
	if cleanArgs == nil {
		return map[string]any{}
	}
	cloned, ok := deepRedactValue(cleanArgs, sc).(map[string]any)
	if !ok {
		return map[string]any{}
	}
	for _, p := range redactPaths {
		redactPathInMap(cloned, strings.Split(p, "."))
	}
	return cloned
}

func deepRedactValue(v any, sc *SecretScanner) any {
	switch x := v.(type) {
	case string:
		return sc.RedactString(x)
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = deepRedactValue(val, sc)
		}
		return m
	case []any:
		arr := make([]any, len(x))
		for i, elem := range x {
			arr[i] = deepRedactValue(elem, sc)
		}
		return arr
	default:
		return x
	}
}

func redactPathInMap(curr any, segments []string) {
	if len(segments) == 0 {
		return
	}
	seg := segments[0]
	isWildcard := strings.HasSuffix(seg, "[*]")
	field := strings.TrimSuffix(seg, "[*]")

	m, ok := curr.(map[string]any)
	if !ok {
		return
	}
	val, exists := m[field]
	if !exists || val == nil {
		return
	}
	if len(segments) == 1 && !isWildcard {
		m[field] = "[REDACTED]"
		return
	}
	if isWildcard {
		arr, isArr := val.([]any)
		if !isArr {
			return
		}
		if len(segments) == 1 {
			for i := range arr {
				arr[i] = "[REDACTED]"
			}
			return
		}
		for _, elem := range arr {
			redactPathInMap(elem, segments[1:])
		}
		return
	}
	redactPathInMap(val, segments[1:])
}
