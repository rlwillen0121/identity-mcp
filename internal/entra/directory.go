package entra

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func (c *Client) listGroups(ctx context.Context, _ *mcp.CallToolRequest, in ListGroupsInput) (*mcp.CallToolResult, idmcp.Page[Group], error) {
	var zero idmcp.Page[Group]
	base, err := c.graphCollectionQuery("/groups", in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	var raw graphPage[graphGroup]
	_, err = c.getJSON400(ctx, "/groups", &raw, queryVariants(base, in.Search, in.Filter, displayNameStartswith(in.Search), groupSelect, "")...)
	if err != nil {
		return nil, zero, err
	}
	items := make([]Group, 0, len(raw.Value))
	for _, g := range raw.Value {
		items = append(items, toGroup(g))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) listGroupMembers(ctx context.Context, _ *mcp.CallToolRequest, in ListGroupMembersInput) (*mcp.CallToolResult, idmcp.Page[DirectoryMember], error) {
	var zero idmcp.Page[DirectoryMember]
	if err := idmcp.Require("group_id", in.GroupID); err != nil {
		return nil, zero, err
	}
	q, err := c.graphCollectionQuery("/groups/"+url.PathEscape(in.GroupID)+"/members", in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	q.Set("$count", "true")
	q.Set("$select", "id,displayName,userPrincipalName")
	path := "/groups/" + url.PathEscape(in.GroupID) + "/members"
	var raw graphPage[graphDirectoryObject]
	_, err = c.getJSON400(ctx, path, &raw, q, withoutSelect(q))
	if err != nil {
		return nil, zero, err
	}
	items := make([]DirectoryMember, 0, len(raw.Value))
	for _, o := range raw.Value {
		items = append(items, toMember(o))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) listDirectoryRoles(ctx context.Context, _ *mcp.CallToolRequest, in ListDirectoryRolesInput) (*mcp.CallToolResult, idmcp.Page[DirectoryRole], error) {
	var zero idmcp.Page[DirectoryRole]
	q, err := c.graphCollectionQuery("/directoryRoles", in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	q.Set("$select", roleSelect)
	var raw graphPage[graphDirectoryRole]
	if err := c.getJSON(ctx, "/directoryRoles", q, &raw); err != nil {
		return nil, zero, err
	}
	items := make([]DirectoryRole, 0, len(raw.Value))
	for _, r := range raw.Value {
		items = append(items, toRole(r))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) listRoleMembers(ctx context.Context, _ *mcp.CallToolRequest, in ListRoleMembersInput) (*mcp.CallToolResult, idmcp.Page[DirectoryMember], error) {
	var zero idmcp.Page[DirectoryMember]
	if err := idmcp.Require("role_id", in.RoleID); err != nil {
		return nil, zero, err
	}
	if strings.TrimSpace(in.SkipToken) != "" {
		return nil, zero, fmt.Errorf("directory role members are not paginated by Graph; omit skip_token")
	}
	q := url.Values{}
	q.Set("$select", "id,displayName,userPrincipalName")
	path := "/directoryRoles/" + url.PathEscape(in.RoleID) + "/members"
	var raw graphPage[graphDirectoryObject]
	if _, err := c.getJSON400(ctx, path, &raw, q, withoutSelect(q)); err != nil {
		return nil, zero, err
	}
	items := make([]DirectoryMember, 0, len(raw.Value))
	for _, o := range raw.Value {
		items = append(items, toMember(o))
	}
	limit := in.Limit
	if limit <= 0 {
		limit = idmcp.DefaultLimit
	}
	if limit > 1000 {
		limit = 1000
	}
	truncated := len(items) > limit
	if truncated {
		items = items[:limit]
	}
	if items == nil {
		items = []DirectoryMember{}
	}
	return nil, idmcp.Page[DirectoryMember]{Items: items, Truncated: truncated}, nil
}

func (c *Client) listServicePrincipals(ctx context.Context, _ *mcp.CallToolRequest, in ListServicePrincipalsInput) (*mcp.CallToolResult, idmcp.Page[ServicePrincipal], error) {
	var zero idmcp.Page[ServicePrincipal]
	base, err := c.graphCollectionQuery("/servicePrincipals", in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	var raw graphPage[graphServicePrincipal]
	_, err = c.getJSON400(ctx, "/servicePrincipals", &raw, queryVariants(base, in.Search, in.Filter, displayNameStartswith(in.Search), spSelect, "")...)
	if err != nil {
		return nil, zero, err
	}
	items := make([]ServicePrincipal, 0, len(raw.Value))
	for _, s := range raw.Value {
		items = append(items, toSP(s))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) listSignIns(ctx context.Context, _ *mcp.CallToolRequest, in ListSignInsInput) (*mcp.CallToolResult, idmcp.Page[SignIn], error) {
	var zero idmcp.Page[SignIn]
	q, err := c.graphCollectionQuery("/auditLogs/signIns", clampSignIns(in.Limit), in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	q.Set("$top", strconv.Itoa(clampSignIns(in.Limit)))
	q.Set("$select", "id,createdDateTime,userPrincipalName,appDisplayName,ipAddress,status,conditionalAccessStatus")

	var parts []string
	if in.Filter != "" {
		parts = append(parts, in.Filter)
	}
	if in.UserID != "" {
		if strings.Contains(in.UserID, "@") {
			parts = append(parts, fmt.Sprintf("userPrincipalName eq '%s'", odataStr(in.UserID)))
		} else {
			parts = append(parts, fmt.Sprintf("userId eq '%s'", odataStr(in.UserID)))
		}
	}
	if len(parts) > 0 {
		q.Set("$filter", strings.Join(parts, " and "))
	}

	var raw graphPage[graphSignIn]
	if err := c.getJSON(ctx, "/auditLogs/signIns", q, &raw); err != nil {
		return nil, zero, err
	}
	items := make([]SignIn, 0, len(raw.Value))
	for _, s := range raw.Value {
		items = append(items, toSignIn(s))
	}
	return nil, pageOf(items, raw.NextLink), nil
}
