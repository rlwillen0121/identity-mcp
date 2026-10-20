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
	return NewServerWithOptions(client, false)
}

func NewServerWithOptions(client *idmcp.Client, enableWrites bool) *mcp.Server {
	s := NewService(client)
	srv := idmcp.NewServer(implementationName, implementationVer)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_users",
		Title:       "List users",
		Description: "Use when you need to find people in Lumos by name or email. Pages with an integer page cursor (next). Prefer search_term over dumping the whole org.",
		Annotations: idmcp.ReadOnly("List users"),
	}, s.ListUsers)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_user",
		Title:       "Get user",
		Description: "Use when you already have a Lumos user id and need that identity's profile (email, given/family name, status).",
		Annotations: idmcp.ReadOnly("Get user"),
	}, s.GetUser)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_user_access",
		Title:       "Get user access",
		Description: "Use when asking what a person has in Lumos. Composes GET /users/{id}, /users/{id}/accounts (expand=app, at most 50), and /users/{id}/roles into one result: profile, Lumos roles, and app accounts with last_login when present.",
		Annotations: idmcp.ReadOnly("Get user access"),
	}, s.GetUserAccess)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_apps",
		Title:       "List apps",
		Description: "Use when you need the apps Lumos knows about before listing accounts or starting an access review.",
		Annotations: idmcp.ReadOnly("List apps"),
	}, s.ListApps)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_app_accounts",
		Title:       "List app accounts",
		Description: "Use when you have an app id and need who has an account on that app (optional status filter). Expand includes app name.",
		Annotations: idmcp.ReadOnly("List app accounts"),
	}, s.ListAppAccounts)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_groups",
		Title:       "List groups",
		Description: "Use when looking up Lumos groups (synced from connected integrations) before inspecting membership.",
		Annotations: idmcp.ReadOnly("List groups"),
	}, s.ListGroups)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_group_members",
		Title:       "List group members",
		Description: "Use when you have a Lumos group id and need the users in it for an access review.",
		Annotations: idmcp.ReadOnly("List group members"),
	}, s.ListGroupMembers)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "find_stale_accounts",
		Title:       "Find stale accounts",
		Description: "Use when asked for unused, dormant, or deprovision-pending app accounts. Flags SUSPENDED/ARCHIVED/DEPROVISIONED/ACCESS_REMOVED/WAITING_MANUAL_REMOVAL, missing last_login (no_login), and last_login older than inactive_days (default 90). Inspects at most 500 accounts. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		Annotations: idmcp.ReadOnly("Find stale accounts"),
	}, s.FindStaleAccounts)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_access_reviews",
		Title:       "List access reviews",
		Description: "Use when you need open or recent Lumos access-review campaigns (status, deadline, apps). Read-only; does not create or complete reviews.",
		Annotations: idmcp.ReadOnly("List access reviews"),
	}, s.ListAccessReviews)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_activity_logs",
		Title:       "List activity logs",
		Description: "Use when investigating who requested, approved, or provisioned access. GET /activity_logs with since/until; cap 100. Pages with an integer offset cursor from next — do not pass URLs from links.next.",
		Annotations: idmcp.ReadOnly("List activity logs"),
	}, s.ListActivityLogs)

	if enableWrites {
		mcp.AddTool(srv, &mcp.Tool{
			Name:        "create_access_request",
			Title:       "Create access request",
			Description: "Use when requesting access to an application on behalf of a Lumos user. Creates an access request workflow in Lumos. Opt-in mutating tool.",
			Annotations: idmcp.Write("Create access request", false, false),
		}, s.CreateAccessRequest)

		mcp.AddTool(srv, &mcp.Tool{
			Name:        "remove_group_member",
			Title:       "Remove group member",
			Description: "Use when removing a user from a Lumos group for access offboarding or remediation. Opt-in mutating tool.",
			Annotations: idmcp.Write("Remove group member", true, true),
		}, s.RemoveGroupMember)
	}

	return srv
}
