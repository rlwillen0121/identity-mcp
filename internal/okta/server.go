package okta

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const (
	implementationName = "okta-mcp"
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

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_users",
		Title:       "List users",
		Description: "List or search Okta users. Use when you need to find people by login, email, or status, or page through the directory. Prefer Okta search expressions (profile.email eq \"user@example.com\") over dumping the whole org.",
		Annotations: idmcp.ReadOnly("List users"),
	}, s.ListUsers)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_user",
		Title:       "Get user",
		Description: "Fetch one Okta user by id or login. Use when you already have a specific user and need profile details (name, department, title, employeeNumber).",
		Annotations: idmcp.ReadOnly("Get user"),
	}, s.GetUser)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_user_groups",
		Title:       "List user groups",
		Description: "List Okta groups for a user id. Use for access reviews, membership checks, or answering which groups a person belongs to.",
		Annotations: idmcp.ReadOnly("List user groups"),
	}, s.ListUserGroups)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_groups",
		Title:       "List groups",
		Description: "List or search Okta groups. Use when looking up a group by name (q) or filter before inspecting membership.",
		Annotations: idmcp.ReadOnly("List groups"),
	}, s.ListGroups)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_group_users",
		Title:       "List group users",
		Description: "List members of an Okta group. Use when you have a group id and need the people in it for an access review or membership dump.",
		Annotations: idmcp.ReadOnly("List group users"),
	}, s.ListGroupUsers)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_apps",
		Title:       "List apps",
		Description: "List or search Okta applications. Use when finding an SSO app by name/label before listing its assigned users.",
		Annotations: idmcp.ReadOnly("List apps"),
	}, s.ListApps)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_app_users",
		Title:       "List app users",
		Description: "List users assigned to an Okta application. Use when you have an app id and need who has access to that app.",
		Annotations: idmcp.ReadOnly("List app users"),
	}, s.ListAppUsers)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_admins",
		Title:       "List admins",
		Description: "List Okta users with admin/IAM role assignments. Use for privileged-access reviews. Calls GET /api/v1/iam/assignees/users (requires okta.roles.read / an admin API token), then GET /api/v1/users/{id} and /users/{id}/roles for login, email, and role labels. Do not treat all ACTIVE users as admins.",
		Annotations: idmcp.ReadOnly("List admins"),
	}, s.ListAdmins)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "find_stale_users",
		Title:       "Find stale users",
		Description: "Find dormant or never-used Okta accounts for IGA review. Use when asked for unused, stale, or inactive users. Flags missing lastLogin (no_login), lastLogin older than inactive_days (default 90), and non-active statuses STAGED, PROVISIONED, and PASSWORD_EXPIRED. Inspects at most 500 accounts. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		Annotations: idmcp.ReadOnly("Find stale users"),
	}, s.FindStaleUsers)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_logs",
		Title:       "List logs",
		Description: "Query the Okta System Log. Use when investigating sign-in, app access, or admin-change events in a time window (since/until) or by eventType filter. Returns at most 100 events per call. since and after are mutually exclusive: when paging with after, omit since/until.",
		Annotations: idmcp.ReadOnly("List logs"),
	}, s.ListLogs)

	return srv
}
