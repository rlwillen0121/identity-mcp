package sailpoint

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const (
	implementationName = "sailpoint-mcp"
	implementationVer  = "0.2.0"
)

func NewServer(c *Client) *mcp.Server {
	s := idmcp.NewServer(implementationName, implementationVer)
	addTool(s, "list_identities", "List identities",
		"Use when you need to find ISC identities (filters, sorters, defaultFilter CORRELATED_ONLY unless NONE). Pages with an integer offset cursor from next.",
		c.listIdentities)
	addTool(s, "get_identity", "Get identity",
		"Use when you already have an identity id and need that identity's profile (name, alias, email, identity state, cloud lifecycle).",
		c.getIdentity)
	addTool(s, "get_identity_access", "Get identity access",
		"Use when asking what an identity has across sources. Composes GET /identities/{id}, /accounts (identityId, SLIM, cap 50), /entitlements/identities/{id}/entitlements (cap 50), and /identities/{id}/role-assignments (cap 50).",
		c.getIdentityAccess)
	addTool(s, "list_accounts", "List accounts",
		"Use when listing source accounts by a raw ISC filters string (identityId, sourceId, …). Sends detailLevel=SLIM.",
		c.listAccounts)
	addTool(s, "list_uncorrelated_accounts", "List uncorrelated accounts",
		"Use for the classic IGA hole: accounts not correlated to an identity. Always includes uncorrelated eq true; extra filters are ANDed unless they already mention uncorrelated.",
		c.listUncorrelatedAccounts)
	addTool(s, "list_sources", "List sources",
		"Use when you need the connected sources (name, type, health/status) before inspecting accounts.",
		c.listSources)
	addTool(s, "search", "Search",
		"Use when you need ISC search (identities, entitlements, events, account activities). POST /search with a query string; includeNested defaults false; cap 50. Prefer this over dumping list endpoints.",
		c.search)
	addTool(s, "find_stale_identities", "Find stale identities",
		"Use when asked for inactive or unused identities. Searches identities with inactive lifecycle/state and appends a bounded uncorrelated-account sample. Inspects at most 500 identity rows. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		c.findStaleIdentities)
	addTool(s, "list_account_activities", "List account activities",
		"Use when you need provisioning or access-request evidence (regarding-identity, filters). Cap 100. A PAT with only idn:identity:read, idn:accounts:read, idn:sources:read, idn:entitlement:read, and sp:search:read gets 403; use the search tool with the accountactivities index instead.",
		c.listAccountActivities)
	addTool(s, "list_entitlements", "List entitlements",
		"Use when finding an entitlement (filters on name, source, value) before asking who has it.",
		c.listEntitlements)
	return s
}

func addTool[In, Out any](s *mcp.Server, name, title, desc string, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        name,
		Title:       title,
		Description: desc,
		Annotations: idmcp.ReadOnly(title),
	}, h)
}
