package c1

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const (
	implementationName = "c1-mcp"
	implementationVer  = "0.2.0"
)

func NewServer(c *Client) *mcp.Server {
	s := idmcp.NewServer(implementationName, implementationVer)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_users",
		Title:       "List users",
		Description: "Use when you need to find ConductorOne users by query, email, user_status (ENABLED, DISABLED, DELETED), or role_id. Pages with an opaque page_token. next is nextPageToken.",
		Annotations: idmcp.ReadOnly("List users"),
	}, c.listUsers)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_user",
		Title:       "Get user",
		Description: "Use when you already have a ConductorOne user id. Returns the slim user plus role_ids. role_names are filled from a role_ids expand when that search succeeds; a failed or empty expand still returns the user.",
		Annotations: idmcp.ReadOnly("Get user"),
	}, c.getUser)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_user_access",
		Title:       "Get user access",
		Description: "Use when asking what a person has in ConductorOne. Composes GET /users/{id}, one app-user search (expand last_usage, cap 50), and one grants search (cap 50, no expand). Does not follow a second grants page.",
		Annotations: idmcp.ReadOnly("Get user access"),
	}, c.getUserAccess)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_apps",
		Title:       "List apps",
		Description: "Use when you need ConductorOne apps (id, display name, description, directory flag) before listing accounts or entitlements.",
		Annotations: idmcp.ReadOnly("List apps"),
	}, c.listApps)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_app_users",
		Title:       "List app users",
		Description: "Use when you have an app id and need accounts on that app. Optional status (STATUS_ENABLED, STATUS_DISABLED, STATUS_DELETED) and type (APP_USER_TYPE_USER, APP_USER_TYPE_SERVICE_ACCOUNT, APP_USER_TYPE_SYSTEM_ACCOUNT; SERVICE_ACCOUNT and SYSTEM_ACCOUNT are aliases).",
		Annotations: idmcp.ReadOnly("List app users"),
	}, c.listAppUsers)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_entitlements",
		Title:       "List entitlements",
		Description: "Use when finding an entitlement (optional app_id) before asking who has it. No expand.",
		Annotations: idmcp.ReadOnly("List entitlements"),
	}, c.listEntitlements)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_uncorrelated_accounts",
		Title:       "List uncorrelated accounts",
		Description: "Use for app accounts with no responsible party. Always sends withoutResponsibleParty=true. Optional app_id and query.",
		Annotations: idmcp.ReadOnly("List uncorrelated accounts"),
	}, c.listUncorrelatedAccounts)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "find_stale_accounts",
		Title:       "Find stale accounts",
		Description: "Use when asked for disabled, deleted, unused, or dormant ConductorOne app accounts. Flags STATUS_DISABLED, STATUS_DELETED, missing last usage (no_usage), and last usage older than inactive_days (default 90, reason usage_older_than_N_days). Unknown non-RFC3339 timestamps are not invented. Inspects at most 500 rows. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		Annotations: idmcp.ReadOnly("Find stale accounts"),
	}, c.findStaleAccounts)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_access_reviews",
		Title:       "List access reviews",
		Description: "Use when you need ConductorOne access-review campaigns (state, created time). Read-only; does not create or complete reviews. GET page_size and page_token.",
		Annotations: idmcp.ReadOnly("List access reviews"),
	}, c.listAccessReviews)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_tasks",
		Title:       "List tasks",
		Description: "Use when you need ConductorOne tasks (grant, revoke, certify, offboarding, action, finding) filtered by user, app, access review, or state. Page size is at most 10. Read-only: no approve, complete, or reassign.",
		Annotations: idmcp.ReadOnly("List tasks"),
	}, c.listTasks)

	return s
}
