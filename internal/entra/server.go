package entra

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func NewServer(c *Client) *mcp.Server {
	return NewServerWithOptions(c, false)
}

func NewServerWithOptions(c *Client, enableWrites bool) *mcp.Server {
	s := idmcp.NewServer("entra-mcp", "0.2.0")

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_users",
		Title:       "List users",
		Description: "Use when you need to search or page through Entra ID users and do not already have a user object id. Supports $search/$filter and skip_token pagination.",
		Annotations: idmcp.ReadOnly("List users"),
	}, c.listUsers)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_user",
		Title:       "Get user",
		Description: "Use when you already have a user object id or userPrincipalName and need that user's profile plus up to 50 group memberships.",
		Annotations: idmcp.ReadOnly("Get user"),
	}, c.getUser)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_user_groups",
		Title:       "List user groups",
		Description: "Use when you know a user id and need the groups they belong to (memberOf filtered to #microsoft.graph.group).",
		Annotations: idmcp.ReadOnly("List user groups"),
	}, c.listUserGroups)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_groups",
		Title:       "List groups",
		Description: "Use when you need to search or filter Entra groups (security, Microsoft 365, dynamic membership).",
		Annotations: idmcp.ReadOnly("List groups"),
	}, c.listGroups)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_group_members",
		Title:       "List group members",
		Description: "Use when you have a group id and need its members (users, nested groups, or service principals). Sends $count=true because Graph requires advanced queries for $select/$top on this collection.",
		Annotations: idmcp.ReadOnly("List group members"),
	}, c.listGroupMembers)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_directory_roles",
		Title:       "List directory roles",
		Description: "Use when you need the activated Entra directory roles in the tenant (for example Global Administrator).",
		Annotations: idmcp.ReadOnly("List directory roles"),
	}, c.listDirectoryRoles)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_role_members",
		Title:       "List role members",
		Description: "Use when you have a directory role id and need the principals assigned to that role. Graph does not paginate this collection ($top/$skiptoken are not sent); limit caps the in-memory result (max 1000).",
		Annotations: idmcp.ReadOnly("List role members"),
	}, c.listRoleMembers)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_service_principals",
		Title:       "List service principals",
		Description: "Use when investigating non-human identities, enterprise apps, or orphaned applications. Lists service principals with app id and owner tenant.",
		Annotations: idmcp.ReadOnly("List service principals"),
	}, c.listServicePrincipals)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "find_stale_users",
		Title:       "Find stale users",
		Description: "Use for joiner-mover-leaver and access reviews: find disabled users or users with no sign-in / sign-in older than inactive_days (default 90). Inspects at most 500 accounts. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		Annotations: idmcp.ReadOnly("Find stale users"),
	}, c.findStaleUsers)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_sign_ins",
		Title:       "List sign-ins",
		Description: "Use when you need recent Entra sign-in audit log rows for a user or $filter (for example createdDateTime ge ...). Requires AuditLog.Read.All. Max 50 rows.",
		Annotations: idmcp.ReadOnly("List sign-ins"),
	}, c.listSignIns)

	if enableWrites {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "add_group_member",
			Title:       "Add group member",
			Description: "Add a user to an Entra ID group by posting a directoryObject reference to /groups/{group_id}/members/$ref.",
			Annotations: idmcp.Write("Add group member", false, false),
		}, c.addGroupMember)

		mcp.AddTool(s, &mcp.Tool{
			Name:        "revoke_sign_in_sessions",
			Title:       "Revoke sign-in sessions",
			Description: "Invalidate all refresh tokens and sessions for an Entra ID user by calling /users/{user_id}/revokeSignInSessions.",
			Annotations: idmcp.Write("Revoke sign-in sessions", true, false),
		}, c.revokeSignInSessions)
	}

	return s
}
