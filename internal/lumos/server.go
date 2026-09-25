package lumos

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const (
	implementationName = "lumos-mcp"
	implementationVer  = "0.2.0"
)

type Service struct {
	client *idmcp.Client
}

func NewService(client *idmcp.Client) *Service {
	return &Service{client: client}
}

func NewServer(client *idmcp.Client) *mcp.Server {
	s := NewService(client)
	srv := idmcp.NewServer(implementationName, implementationVer)
	addTool(srv, "list_users", "List users",
		"Use when you need to find people in Lumos by name or email. Pages with an integer page cursor (next). Prefer search_term over dumping the whole org.",
		s.ListUsers)
	addTool(srv, "get_user", "Get user",
		"Use when you already have a Lumos user id and need that identity's profile (email, given/family name, status).",
		s.GetUser)
	addTool(srv, "get_user_access", "Get user access",
		"Use when asking what a person has in Lumos. Composes GET /users/{id}, /users/{id}/accounts (expand=app, at most 50), and /users/{id}/roles into one result: profile, Lumos roles, and app accounts with last_login when present.",
		s.GetUserAccess)
	addTool(srv, "list_apps", "List apps",
		"Use when you need the apps Lumos knows about before listing accounts or starting an access review.",
		s.ListApps)
	addTool(srv, "list_app_accounts", "List app accounts",
		"Use when you have an app id and need who has an account on that app (optional status filter). Expand includes app name.",
		s.ListAppAccounts)
	addTool(srv, "list_groups", "List groups",
		"Use when looking up Lumos groups (synced from connected integrations) before inspecting membership.",
		s.ListGroups)
	addTool(srv, "list_group_members", "List group members",
		"Use when you have a Lumos group id and need the users in it for an access review.",
		s.ListGroupMembers)
	addTool(srv, "find_stale_accounts", "Find stale accounts",
		"Use when asked for unused, dormant, or deprovision-pending app accounts. Flags SUSPENDED/ARCHIVED/DEPROVISIONED/ACCESS_REMOVED/WAITING_MANUAL_REMOVAL, missing last_login (no_login), and last_login older than inactive_days (default 90). Inspects at most 500 accounts. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		s.FindStaleAccounts)
	addTool(srv, "list_access_reviews", "List access reviews",
		"Use when you need open or recent Lumos access-review campaigns (status, deadline, apps). Read-only; does not create or complete reviews.",
		s.ListAccessReviews)
	addTool(srv, "list_activity_logs", "List activity logs",
		"Use when investigating who requested, approved, or provisioned access. GET /activity_logs with since/until; cap 100. Pages with an integer offset cursor from next — do not pass URLs from links.next.",
		s.ListActivityLogs)
	return srv
}

func addTool[In, Out any](s *mcp.Server, name, title, desc string, h mcp.ToolHandlerFor[In, Out]) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        name,
		Title:       title,
		Description: desc,
		Annotations: idmcp.ReadOnly(title),
	}, h)
}
