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
	return NewServerWithOptions(c, false)
}

func NewServerWithOptions(c *Client, enableWrites bool) *mcp.Server {
	s := idmcp.NewServer(implementationName, implementationVer)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_identities",
		Title:       "List identities",
		Description: "Use when you need to find ISC identities (filters, sorters, defaultFilter CORRELATED_ONLY unless NONE). Pages with an integer offset cursor from next.",
		Annotations: idmcp.ReadOnly("List identities"),
	}, c.listIdentities)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_identity",
		Title:       "Get identity",
		Description: "Use when you already have an identity id and need that identity's profile (name, alias, email, identity state, cloud lifecycle).",
		Annotations: idmcp.ReadOnly("Get identity"),
	}, c.getIdentity)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_identity_access",
		Title:       "Get identity access",
		Description: "Use when asking what an identity has across sources. Composes GET /identities/{id}, /accounts (identityId, SLIM, cap 50), /entitlements/identities/{id}/entitlements (cap 50), and /identities/{id}/role-assignments (cap 50).",
		Annotations: idmcp.ReadOnly("Get identity access"),
	}, c.getIdentityAccess)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_accounts",
		Title:       "List accounts",
		Description: "Use when listing source accounts by a raw ISC filters string (identityId, sourceId, …). Sends detailLevel=SLIM.",
		Annotations: idmcp.ReadOnly("List accounts"),
	}, c.listAccounts)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_uncorrelated_accounts",
		Title:       "List uncorrelated accounts",
		Description: "Use for the classic IGA hole: accounts not correlated to an identity. Always includes uncorrelated eq true; extra filters are ANDed unless they already mention uncorrelated.",
		Annotations: idmcp.ReadOnly("List uncorrelated accounts"),
	}, c.listUncorrelatedAccounts)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_sources",
		Title:       "List sources",
		Description: "Use when you need the connected sources (name, type, health/status) before inspecting accounts.",
		Annotations: idmcp.ReadOnly("List sources"),
	}, c.listSources)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "search",
		Title:       "Search",
		Description: "Use when you need ISC search (identities, entitlements, events, account activities). POST /search with a query string; includeNested defaults false; cap 50. Prefer this over dumping list endpoints.",
		Annotations: idmcp.ReadOnly("Search"),
	}, c.search)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "find_stale_identities",
		Title:       "Find stale identities",
		Description: "Use when asked for inactive or unused identities. Searches identities with inactive lifecycle/state and appends a bounded uncorrelated-account sample. Inspects at most 500 identity rows. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		Annotations: idmcp.ReadOnly("Find stale identities"),
	}, c.findStaleIdentities)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_account_activities",
		Title:       "List account activities",
		Description: "Use when you need provisioning or access-request evidence (regarding-identity, filters). Cap 100. A PAT with only idn:identity:read, idn:accounts:read, idn:sources:read, idn:entitlement:read, and sp:search:read gets 403; use the search tool with the accountactivities index instead.",
		Annotations: idmcp.ReadOnly("List account activities"),
	}, c.listAccountActivities)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_entitlements",
		Title:       "List entitlements",
		Description: "Use when finding an entitlement (filters on name, source, value) before asking who has it.",
		Annotations: idmcp.ReadOnly("List entitlements"),
	}, c.listEntitlements)

	if enableWrites {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "create_access_request",
			Title:       "Create access request",
			Description: "Create a SailPoint ISC access request for an identity to grant an entitlement (POST /access-requests). Opt-in write tool; requires --enable-writes.",
			Annotations: idmcp.Write("Create access request", false, false),
		}, c.createAccessRequest)

		mcp.AddTool(s, &mcp.Tool{
			Name:        "disable_account",
			Title:       "Disable account",
			Description: "Disable a SailPoint ISC source account (POST /accounts/{account_id}/disable). Destructive opt-in write tool; requires --enable-writes.",
			Annotations: idmcp.Write("Disable account", true, true),
		}, c.disableAccount)
	}

	return s
}
