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
	path := collectionPath("/groups", in.SkipToken)
	var raw graphPage[graphGroup]
	var err error
	if isAbsURL(path) {
		err = c.getJSON(ctx, path, nil, &raw)
	} else {
		base := collectionQuery(in.Limit, in.SkipToken)
		_, err = c.getJSON400(ctx, path, &raw, queryVariants(base, in.Search, in.Filter, displayNameStartswith(in.Search), groupSelect, "")...)
	}
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
	path := collectionPath("/groups/"+url.PathEscape(in.GroupID)+"/members", in.SkipToken)
	var raw graphPage[graphDirectoryObject]
	var err error
	if isAbsURL(path) {
		err = c.getJSON(ctx, path, nil, &raw)
	} else {
		q := collectionQuery(in.Limit, in.SkipToken)
		q.Set("$select", "id,displayName,userPrincipalName")
		err = c.getJSON(ctx, path, q, &raw)
	}
	if err != nil {
		return nil, zero, err
	}
	items := make([]DirectoryMember, 0, len(raw.Value))
	for _, o := range raw.Value {
		items = append(items, toMember(o))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) listDirectoryRoles(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, idmcp.Page[DirectoryRole], error) {
	var zero idmcp.Page[DirectoryRole]
	q := url.Values{}
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
	path := "/directoryRoles/" + url.PathEscape(in.RoleID) + "/members"
	q := url.Values{}
	q.Set("$select", "id,displayName,userPrincipalName")
	q.Set("$top", strconv.Itoa(idmcp.ClampLimit(in.Limit)))
	var raw graphPage[graphDirectoryObject]
	if err := c.getJSON(ctx, path, q, &raw); err != nil {
		return nil, zero, err
	}
	items := make([]DirectoryMember, 0, len(raw.Value))
	for _, o := range raw.Value {
		items = append(items, toMember(o))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) listServicePrincipals(ctx context.Context, _ *mcp.CallToolRequest, in ListServicePrincipalsInput) (*mcp.CallToolResult, idmcp.Page[ServicePrincipal], error) {
	var zero idmcp.Page[ServicePrincipal]
	path := collectionPath("/servicePrincipals", in.SkipToken)
	var raw graphPage[graphServicePrincipal]
	var err error
	if isAbsURL(path) {
		err = c.getJSON(ctx, path, nil, &raw)
	} else {
		base := collectionQuery(in.Limit, in.SkipToken)
		_, err = c.getJSON400(ctx, path, &raw, queryVariants(base, in.Search, in.Filter, displayNameStartswith(in.Search), spSelect, "")...)
	}
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
	q := url.Values{}
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
