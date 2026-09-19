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
	base, err := collectionQuery(in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	var raw graphPage[graphUser]
	_, err = c.getJSON400(ctx, "/users", &raw, queryVariants(base, in.Search, in.Filter, userStartswith(in.Search), userSelect, userSelectNoSignIn)...)
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

	groups, next, err := c.memberOf(ctx, in.UserID, 50, "")
	if err != nil {
		return nil, zero, err
	}
	if groups == nil {
		groups = []GroupRef{}
	}
	u := toUser(raw)
	out := UserDetail{
		ID:              u.ID,
		DisplayName:     u.DisplayName,
		UPN:             u.UPN,
		Mail:            u.Mail,
		Enabled:         u.Enabled,
		Created:         u.Created,
		UserType:        u.UserType,
		JobTitle:        u.JobTitle,
		Department:      u.Department,
		LastSignIn:      u.LastSignIn,
		Groups:          groups,
		GroupsTruncated: next != "",
	}
	return nil, out, nil
}

func (c *Client) listUserGroups(ctx context.Context, _ *mcp.CallToolRequest, in ListUserGroupsInput) (*mcp.CallToolResult, idmcp.Page[GroupRef], error) {
	var zero idmcp.Page[GroupRef]
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, zero, err
	}
	groups, next, err := c.memberOf(ctx, in.UserID, in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	return nil, pageOf(groups, next), nil
}

func (c *Client) memberOf(ctx context.Context, userID string, limit int, skipToken string) ([]GroupRef, string, error) {
	q, err := collectionQuery(limit, skipToken)
	if err != nil {
		return nil, "", err
	}
	q.Set("$count", "true")
	q.Set("$select", memberOfSelect)
	cast := "/users/" + url.PathEscape(userID) + "/memberOf/microsoft.graph.group"
	uncast := "/users/" + url.PathEscape(userID) + "/memberOf"
	var raw graphPage[graphDirectoryObject]
	if _, err := c.getJSON400(ctx, cast, &raw, q, withoutSelect(q)); err != nil {
		if _, err2 := c.getJSON400(ctx, uncast, &raw, q, withoutSelect(q)); err2 != nil {
			return nil, "", err
		}
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

	skip, err := idmcp.OpaqueCursor(in.SkipToken, "$skiptoken")
	if err != nil {
		return nil, zero, err
	}
	items := make([]StaleUser, 0)
	scanned := 0
	noSignInData := false
	var nextLink string
	for page := 0; page < idmcp.MaxStalePages && len(items) < limit; page++ {
		q := url.Values{}
		q.Set("$top", strconv.Itoa(idmcp.DefaultLimit))
		if skip != "" {
			q.Set("$skiptoken", skip)
		}
		q.Set("$select", userSelect)
		var raw graphPage[graphUser]
		err := c.getJSON(ctx, "/users", q, &raw)
		if isRetryableSelect(err) {
			q.Set("$select", userSelectNoSignIn)
			err = c.getJSON(ctx, "/users", q, &raw)
			noSignInData = true
		}
		if err != nil {
			return nil, zero, err
		}
		scanned += len(raw.Value)
		leftover := false
		for _, u := range raw.Value {
			su, ok := classifyStale(u, cutoff, reasonOld, noSignInData)
			if !ok {
				continue
			}
			if len(items) >= limit {
				leftover = true
				continue
			}
			items = append(items, su)
		}
		nextLink = raw.NextLink
		if leftover {
			out := FindStaleUsersOutput{Items: items, Truncated: true, Scanned: scanned}
			if noSignInData {
				out.Note = "signInActivity unavailable; last_sign_in unknown. Returning disabled users only."
			}
			return nil, out, nil
		}
		skip = extractSkipToken(raw.NextLink)
		if skip == "" || len(raw.Value) == 0 {
			break
		}
	}
	out := FindStaleUsersOutput{
		Items:     items,
		Next:      extractSkipToken(nextLink),
		Truncated: nextLink != "",
		Scanned:   scanned,
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
