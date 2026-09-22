package entra

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func (c *Client) listUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListUsersInput) (*mcp.CallToolResult, idmcp.Page[User], error) {
	var zero idmcp.Page[User]
	base, err := c.graphCollectionQuery("/users", in.Limit, in.SkipToken)
	if err != nil {
		return nil, zero, err
	}
	var raw graphPage[graphUser]
	variant, err := c.getJSON400(ctx, "/users", &raw, queryVariants(base, in.Search, in.Filter, userStartswith(in.Search), userSelect, userSelectNoSignIn)...)
	if err != nil {
		return nil, zero, err
	}
	activityAvailable := variant%2 == 0
	items := make([]User, 0, len(raw.Value))
	for _, u := range raw.Value {
		items = append(items, toUserWithSignInActivity(u, activityAvailable))
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
	variant, err := c.getJSON400(ctx, path, &raw,
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
	u := toUserWithSignInActivity(raw, variant == 0)
	out := UserDetail{
		ID:                      u.ID,
		DisplayName:             u.DisplayName,
		UPN:                     u.UPN,
		Mail:                    u.Mail,
		Enabled:                 u.Enabled,
		Created:                 u.Created,
		UserType:                u.UserType,
		JobTitle:                u.JobTitle,
		Department:              u.Department,
		LastSignIn:              u.LastSignIn,
		SignInActivityAvailable: u.SignInActivityAvailable,
		Groups:                  groups,
		GroupsTruncated:         next != "",
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
	cast := "/users/" + url.PathEscape(userID) + "/memberOf/microsoft.graph.group"
	uncast := "/users/" + url.PathEscape(userID) + "/memberOf"
	path, cursor, err := memberOfCursor(skipToken, cast, uncast)
	if err != nil {
		return nil, "", err
	}
	if strings.Contains(cursor, "://") || strings.HasPrefix(cursor, "/") {
		u, err := url.Parse(cursor)
		if err != nil {
			return nil, "", fmt.Errorf("invalid Graph pagination cursor")
		}
		base, err := url.Parse(c.graph.BaseURL)
		if err != nil || (u.IsAbs() && (u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host))) {
			return nil, "", fmt.Errorf("Graph pagination cursor authority does not match configured Graph endpoint")
		}
		basePath := strings.TrimRight(base.Path, "/")
		if u.Path == basePath+uncast {
			path = uncast
		} else if u.Path != basePath+cast {
			return nil, "", fmt.Errorf("Graph pagination cursor path does not match memberOf")
		}
	}
	q, err := c.graphCollectionQuery(path, limit, cursor)
	if err != nil {
		return nil, "", err
	}
	q.Set("$count", "true")
	q.Set("$select", memberOfSelect)
	var raw graphPage[graphDirectoryObject]
	_, castErr := c.getJSON400(ctx, path, &raw, q, withoutSelect(q))
	if castErr != nil {
		if path != cast || !isMemberOfFallbackError(castErr) {
			return nil, "", castErr
		}
		if _, err := c.getJSON400(ctx, uncast, &raw, q, withoutSelect(q)); err != nil {
			return nil, "", err
		}
		path = uncast
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
	next := raw.NextLink
	if path == uncast && next != "" {
		next = encodeMemberOfCursor(next)
	}
	return items, next, nil
}

func isMemberOfFallbackError(err error) bool {
	status := idmcp.StatusOf(err)
	if status != http.StatusBadRequest && status != http.StatusNotFound {
		return false
	}
	var he *idmcp.HTTPError
	if !errors.As(err, &he) {
		return false
	}
	body := strings.ToLower(he.Body)
	if status == http.StatusBadRequest {
		return strings.Contains(body, "request_unsupportedquery") &&
			(strings.Contains(body, "unsupported") || strings.Contains(body, "microsoft.graph.group") || strings.Contains(body, "memberof"))
	}
	return strings.Contains(body, "microsoft.graph.group") && strings.Contains(body, "segment")
}

const memberOfCursorPrefix = "memberof:v1:"

func encodeMemberOfCursor(next string) string {
	return memberOfCursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(next))
}

func memberOfCursor(raw, cast, uncast string) (path, cursor string, err error) {
	if !strings.HasPrefix(raw, memberOfCursorPrefix) {
		return cast, raw, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, memberOfCursorPrefix))
	if err != nil || len(b) == 0 {
		return "", "", fmt.Errorf("invalid memberOf pagination cursor")
	}
	return uncast, string(b), nil
}

func (c *Client) findStaleUsers(ctx context.Context, _ *mcp.CallToolRequest, in FindStaleUsersInput) (*mcp.CallToolResult, FindStaleUsersOutput, error) {
	var zero FindStaleUsersOutput
	cutoff, days, err := inactiveCutoff(in.InactiveDays)
	if err != nil {
		return nil, zero, err
	}
	limit := idmcp.ClampLimit(in.Limit)
	reasonOld := fmt.Sprintf("sign_in_older_than_%d_days", days)

	skip := in.SkipToken
	items := make([]StaleUser, 0)
	scanned := 0
	noSignInData := false
	var nextLink string
	for page := 0; page < idmcp.MaxStalePages && len(items) < limit; page++ {
		q, err := c.graphCollectionQuery("/users", idmcp.DefaultLimit, skip)
		if err != nil {
			return nil, zero, err
		}
		q.Set("$top", strconv.Itoa(idmcp.DefaultLimit))
		q.Set("$select", userSelect)
		var raw graphPage[graphUser]
		err = c.getJSON(ctx, "/users", q, &raw)
		if isRetryableSelectQuery(err, q) {
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
