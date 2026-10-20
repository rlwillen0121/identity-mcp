//go:build unix

package authz

import (
	"regexp"
	"slices"
	"strings"
)

var scopeSyntaxRegex = regexp.MustCompile(`^[a-z0-9_]+(:[a-z0-9_]+){1,3}$`)

// ValidateScopeToken verifies that a scope token matches `^[a-z0-9_]+(:[a-z0-9_]+){1,3}$` and contains no '*'.
func ValidateScopeToken(scope string) bool {
	if strings.Contains(scope, "*") {
		return false
	}
	return scopeSyntaxRegex.MatchString(scope)
}

// PopulateOBOScopes extracts human scopes from the verified JWT claims (or anonymous_scopes when require_jwt=false)
// and computes the effective scope intersection S_eff = S_human ∩ S_agent.
func PopulateOBOScopes(pctx *PrincipalContext, authCfg *PrincipalAuthConfig, agentCfg *AgentProfileConfig) error {
	humanSet := make(map[string]struct{})

	if pctx.Anonymous {
		for _, s := range authCfg.AnonymousScopes {
			if !ValidateScopeToken(s) {
				return NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid anonymous scope %q", s)
			}
			humanSet[s] = struct{}{}
		}
	} else {
		// 1. Extract from scope_claims (space-delimited string or []any of strings)
		for _, claimName := range authCfg.ScopeClaims {
			raw, exists := pctx.Claims[claimName]
			if !exists || raw == nil {
				continue
			}
			switch v := raw.(type) {
			case string:
				for _, tok := range strings.Fields(v) {
					if !ValidateScopeToken(tok) {
						return NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid scope token %q in JWT claim %q", tok, claimName)
					}
					humanSet[tok] = struct{}{}
				}
			case []any:
				for _, elem := range v {
					tok, ok := elem.(string)
					if !ok || !ValidateScopeToken(tok) {
						return NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "invalid scope element in JWT claim %q", claimName)
					}
					humanSet[tok] = struct{}{}
				}
			default:
				return NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT scope claim %q must be a string or string array", claimName)
			}
		}

		// 2. Map identity/group/role claims via claim_to_scope_map
		for claimName, valMap := range authCfg.ClaimToScopeMap {
			raw, exists := pctx.Claims[claimName]
			if !exists || raw == nil {
				continue
			}
			switch v := raw.(type) {
			case string:
				for _, mapped := range valMap[v] {
					humanSet[mapped] = struct{}{}
				}
			case []any:
				for _, elem := range v {
					strElem, ok := elem.(string)
					if !ok {
						return NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT claim %q array contains non-string element", claimName)
					}
					for _, mapped := range valMap[strElem] {
						humanSet[mapped] = struct{}{}
					}
				}
			default:
				return NewError(ErrPrincipalJWTExpiredOrInvalid, 2, "JWT mapped claim %q must be a string or string array", claimName)
			}
		}
	}

	humanScopes := make([]string, 0, len(humanSet))
	for s := range humanSet {
		humanScopes = append(humanScopes, s)
	}
	slices.Sort(humanScopes)
	pctx.HumanScopes = humanScopes

	agentSet := make(map[string]struct{}, len(agentCfg.AllowedScopes))
	for _, s := range agentCfg.AllowedScopes {
		agentSet[s] = struct{}{}
	}

	effSet := make(map[string]struct{})
	for s := range humanSet {
		if _, ok := agentSet[s]; ok {
			effSet[s] = struct{}{}
		}
	}
	pctx.EffectiveScope = effSet
	return nil
}

// AuthorizeToolOBO verifies that S_req(tool) is non-empty and a subset of S_eff.
func AuthorizeToolOBO(pctx *PrincipalContext, requiredScopes []string) error {
	if len(requiredScopes) == 0 {
		return NewError(ErrOBOScopeDenied, 2, "tool has empty required_scopes (default deny)")
	}
	for _, req := range requiredScopes {
		if _, ok := pctx.EffectiveScope[req]; !ok {
			return NewError(ErrOBOScopeDenied, 2, "missing required OBO scope %q in effective intersection", req)
		}
	}
	return nil
}
