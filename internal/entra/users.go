package entra

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func (c *Client) listUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListUsersInput) (*mcp.CallToolResult, idmcp.Page[User], error) {
	var zero idmcp.Page[User]
	path := collectionPath("/users", in.SkipToken)
	var raw graphPage[graphUser]
	var err error
	if isAbsURL(path) {
		err = c.getJSON(ctx, path, nil, &raw)
	} else {
		base := collectionQuery(in.Limit, in.SkipToken)
		_, err = c.getJSON400(ctx, path, &raw, queryVariants(base, in.Search, in.Filter, userStartswith(in.Search), userSelect, userSelectNoSignIn)...)
	}
	if err != nil {
		return nil, zero, err
	}
	items := make([]User, 0, len(raw.Value))
	for _, u := range raw.Value {
		items = append(items, toUser(u))
	}
	return nil, pageOf(items, raw.NextLink), nil
}

func (c *Client) getUser(ctx context.Context, _ *mcp.CallToolRequest, in GetUserInput) (*mcp.CallToolResult, UserDetail, error) {
	var zero UserDetail
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, zero, err
	}
	path := "/users/" + url.PathEscape(in.UserID)
	var raw graphUser
	q := url.Values{}
	_, err := c.getJSON400(ctx, path, &raw,
		withSelect(q, userSelect),
		withSelect(q, userSelectNoSignIn),
	)
	if err != nil {
		return nil, zero, err
	}

	groups, err := c.memberGroups(ctx, in.UserID, 50)
	if err != nil {
		return nil, zero, err
	}
	u := toUser(raw)
	out := UserDetail{
		ID:          u.ID,
		DisplayName: u.DisplayName,
		UPN:         u.UPN,
		Mail:        u.Mail,
		Enabled:     u.Enabled,
		Created:     u.Created,
		UserType:    u.UserType,
		JobTitle:    u.JobTitle,
		Department:  u.Department,
		LastSignIn:  u.LastSignIn,
		Groups:      groups,
	}
	return nil, out, nil
}

func (c *Client) listUserGroups(ctx context.Context, _ *mcp.CallToolRequest, in ListUserGroupsInput) (*mcp.CallToolResult, idmcp.Page[GroupRef], error) {
	var zero idmcp.Page[GroupRef]
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, zero, err
	}
	groups, next, err := c.memberOf(ctx, in.UserID, in.Limit)
	if err != nil {
		return nil, zero, err
	}
	return nil, pageOf(groups, next), nil
}

func (c *Client) memberGroups(ctx context.Context, userID string, limit int) ([]GroupRef, error) {
	groups, _, err := c.memberOf(ctx, userID, limit)
	if err != nil {
		return nil, err
	}
	if groups == nil {
		groups = []GroupRef{}
	}
	return groups, nil
}

func (c *Client) memberOf(ctx context.Context, userID string, limit int) ([]GroupRef, string, error) {
	path := "/users/" + url.PathEscape(userID) + "/memberOf"
	q := url.Values{}
	q.Set("$select", memberOfSelect)
	q.Set("$top", strconv.Itoa(idmcp.ClampLimit(limit)))
	var raw graphPage[graphDirectoryObject]
	if err := c.getJSON(ctx, path, q, &raw); err != nil {
		return nil, "", err
	}
	items := make([]GroupRef, 0)
	for _, o := range raw.Value {
		if !isGroupType(o.ODataType, o.GroupTypes) {
			continue
		}
		gt := o.GroupTypes
		if gt == nil {
			gt = []string{}
		}
		items = append(items, GroupRef{ID: o.ID, DisplayName: o.DisplayName, GroupTypes: gt})
	}
	return items, raw.NextLink, nil
}

func (c *Client) findStaleUsers(ctx context.Context, _ *mcp.CallToolRequest, in FindStaleUsersInput) (*mcp.CallToolResult, FindStaleUsersOutput, error) {
	var zero FindStaleUsersOutput
	days := in.InactiveDays
	if days <= 0 {
		days = 90
	}
	limit := idmcp.ClampLimit(in.Limit)
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	reasonOld := fmt.Sprintf("sign_in_older_than_%d_days", days)

	q := url.Values{}
	q.Set("$top", strconv.Itoa(limit))
	q.Set("$select", userSelect)

	var raw graphPage[graphUser]
	err := c.getJSON(ctx, "/users", q, &raw)
	noSignInData := false
	if isBadRequest(err) {
		q.Set("$select", userSelectNoSignIn)
		err = c.getJSON(ctx, "/users", q, &raw)
		noSignInData = true
	}
	if err != nil {
		return nil, zero, err
	}

	items := make([]StaleUser, 0)
	for _, u := range raw.Value {
		if su, ok := classifyStale(u, cutoff, reasonOld, noSignInData); ok {
			items = append(items, su)
			if len(items) >= limit {
				break
			}
		}
	}

	out := FindStaleUsersOutput{
		Items:     items,
		Next:      extractSkipToken(raw.NextLink),
		Truncated: raw.NextLink != "",
	}
	if noSignInData {
		out.Note = "signInActivity unavailable; last_sign_in unknown. Returning disabled users only."
	}
	return nil, out, nil
}

func classifyStale(u graphUser, cutoff time.Time, reasonOld string, noSignInData bool) (StaleUser, bool) {
	enabled := enabledPtr(u.AccountEnabled)
	last := lastSignIn(u.SignInActivity)
	var reasons []string
	if !enabled {
		reasons = append(reasons, "disabled")
	}
	if noSignInData {
		if len(reasons) == 0 {
			return StaleUser{}, false
		}
		return StaleUser{
			ID:          u.ID,
			DisplayName: u.DisplayName,
			UPN:         u.UserPrincipalName,
			Enabled:     enabled,
			LastSignIn:  "unknown",
			Reasons:     reasons,
		}, true
	}
	if last == "" {
		reasons = append(reasons, "no_sign_in")
	} else if ts, ok := parseGraphTime(last); ok && ts.Before(cutoff) {
		reasons = append(reasons, reasonOld)
	}
	if len(reasons) == 0 {
		return StaleUser{}, false
	}
	return StaleUser{
		ID:          u.ID,
		DisplayName: u.DisplayName,
		UPN:         u.UserPrincipalName,
		Enabled:     enabled,
		LastSignIn:  last,
		Reasons:     reasons,
	}, true
}
