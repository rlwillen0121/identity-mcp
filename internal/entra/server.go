package entra

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func NewServer(c *Client) *mcp.Server {
	s := idmcp.NewServer("entra-mcp", "0.2.0")
	addTool(s, "list_users", "List users",
		"Use when you need to search or page through Entra ID users and do not already have a user object id. Supports $search/$filter and skip_token pagination.",
		c.listUsers)
	addTool(s, "get_user", "Get user",
		"Use when you already have a user object id or userPrincipalName and need that user's profile plus up to 50 group memberships.",
		c.getUser)
	addTool(s, "list_user_groups", "List user groups",
		"Use when you know a user id and need the groups they belong to (memberOf filtered to #microsoft.graph.group).",
		c.listUserGroups)
	addTool(s, "list_groups", "List groups",
		"Use when you need to search or filter Entra groups (security, Microsoft 365, dynamic membership).",
		c.listGroups)
	addTool(s, "list_group_members", "List group members",
		"Use when you have a group id and need its members (users, nested groups, or service principals). Sends $count=true because Graph requires advanced queries for $select/$top on this collection.",
		c.listGroupMembers)
	addTool(s, "list_directory_roles", "List directory roles",
		"Use when you need the activated Entra directory roles in the tenant (for example Global Administrator).",
		c.listDirectoryRoles)
	addTool(s, "list_role_members", "List role members",
		"Use when you have a directory role id and need the principals assigned to that role. Graph does not paginate this collection ($top/$skiptoken are not sent); limit caps the in-memory result (max 1000).",
		c.listRoleMembers)
	addTool(s, "list_service_principals", "List service principals",
		"Use when investigating non-human identities, enterprise apps, or orphaned applications. Lists service principals with app id and owner tenant.",
		c.listServicePrincipals)
	addTool(s, "find_stale_users", "Find stale users",
		"Use for joiner-mover-leaver and access reviews: find disabled users or users with no sign-in / sign-in older than inactive_days (default 90). Inspects at most 500 accounts. If truncated is true and next is empty, more matches exist on the current page — re-call with a larger limit.",
		c.findStaleUsers)
	addTool(s, "list_sign_ins", "List sign-ins",
		"Use when you need recent Entra sign-in audit log rows for a user or $filter (for example createdDateTime ge ...). Requires AuditLog.Read.All. Max 50 rows.",
		c.listSignIns)
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
