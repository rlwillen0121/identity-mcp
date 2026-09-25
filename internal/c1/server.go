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
	addTool(s, "list_users", "List users",
		"Use when you need to find ConductorOne users by query, email, user_status (ENABLED, DISABLED, DELETED), or role_id. Pages with an opaque page_token. next is nextPageToken.",
		c.listUsers)
	addTool(s, "get_user", "Get user",
		"Use when you already have a ConductorOne user id. Returns the slim user plus role_ids. role_names are filled from a role_ids expand when that search succeeds; a failed or empty expand still returns the user.",
		c.getUser)
	addTool(s, "get_user_access", "Get user access",
		"Use when asking what a person has in ConductorOne. Composes GET /users/{id}, one app-user search (expand last_usage, cap 50), and one grants search (cap 50, no expand). Does not follow a second grants page.",
		c.getUserAccess)
	addTool(s, "list_apps", "List apps",
		"Use when you need ConductorOne apps (id, display name, description, directory flag) before listing accounts or entitlements.",
		c.listApps)
	addTool(s, "list_app_users", "List app users",
		"Use when you have an app id and need accounts on that app. Optional status (STATUS_ENABLED, STATUS_DISABLED, STATUS_DELETED) and type (APP_USER_TYPE_USER, APP_USER_TYPE_SERVICE_ACCOUNT, APP_USER_TYPE_SYSTEM_ACCOUNT; SERVICE_ACCOUNT and SYSTEM_ACCOUNT are aliases).",
		c.listAppUsers)
	addTool(s, "list_entitlements", "List entitlements",
		"Use when finding an entitlement (optional app_id) before asking who has it. No expand.",
		c.listEntitlements)
	addTool(s, "list_uncorrelated_accounts", "List uncorrelated accounts",
		"Use for app accounts with no responsible party. Always sends withoutResponsibleParty=true. Optional app_id and query.",
		c.listUncorrelatedAccounts)
	addTool(s, "find_stale_accounts", "Find stale accounts",
		"Use when asked for disabled, deleted, unused, or dormant ConductorOne app accounts. Flags STATUS_DISABLED, STATUS_DELETED, missing last usage (no_usage), and last usage older than inactive_days (default 90, reason usage_older_than_N_days). Unknown non-RFC3339 timestamps are not invented. Inspects at most 500 rows. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		c.findStaleAccounts)
	addTool(s, "list_access_reviews", "List access reviews",
		"Use when you need ConductorOne access-review campaigns (state, created time). Read-only; does not create or complete reviews. GET page_size and page_token.",
		c.listAccessReviews)
	addTool(s, "list_tasks", "List tasks",
		"Use when you need ConductorOne tasks (grant, revoke, certify, offboarding, action, finding) filtered by user, app, access review, or state. Page size is at most 10. Read-only: no approve, complete, or reassign.",
		c.listTasks)
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
