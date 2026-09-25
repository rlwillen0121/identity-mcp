package c1

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

func (c *Client) listUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListUsersInput) (*mcp.CallToolResult, idmcp.Page[UserItem], error) {
	var zero idmcp.Page[UserItem]
	if err := oneOf("user_status", in.UserStatus, "ENABLED", "DISABLED", "DELETED"); err != nil {
		return nil, zero, c.scrub(err)
	}
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	body := searchBody(clampPageSize(in.Limit), token)
	setBody(body, "query", in.Query)
	setBody(body, "email", in.Email)
	if in.UserStatus != "" {
		body["userStatuses"] = []string{in.UserStatus}
	}
	if in.RoleID != "" {
		body["roleIds"] = []string{in.RoleID}
	}
	list, next, _, err := c.postList(ctx, "/api/v1/search/users", body)
	if err != nil {
		return nil, zero, err
	}
	items := make([]UserItem, 0, len(list))
	for _, item := range list {
		items = append(items, userFromItem(item))
	}
	return nil, pageOf(items, next), nil
}

func (c *Client) getUser(ctx context.Context, _ *mcp.CallToolRequest, in GetUserInput) (*mcp.CallToolResult, UserDetail, error) {
	var zero UserDetail
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, zero, c.scrub(err)
	}
	raw, err := c.getRaw(ctx, "/api/v1/users/"+url.PathEscape(in.UserID), nil)
	if err != nil {
		return nil, zero, err
	}
	obj, err := decodeObject(raw)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	view := asMap(obj["userView"])
	if view == nil {
		view = obj
	}
	user := userFromItem(view)
	if user.ID == "" {
		user.ID = in.UserID
	}
	detail := UserDetail{
		ID:          user.ID,
		DisplayName: user.DisplayName,
		Email:       user.Email,
		Username:    user.Username,
		Status:      user.Status,
		Type:        user.Type,
		Department:  user.Department,
		JobTitle:    user.JobTitle,
		RoleIDs:     roleIDsOf(view),
	}
	names, nerr := c.lookupRoleNames(ctx, in.UserID, detail.RoleIDs)
	if nerr == nil && len(names) > 0 {
		detail.RoleNames = names
	}
	return nil, detail, nil
}

func (c *Client) lookupRoleNames(ctx context.Context, id string, roleIDs []string) ([]string, error) {
	body := map[string]any{
		"refs":       []map[string]string{{"id": id}},
		"expandMask": map[string]any{"paths": []string{"role_ids"}},
		"pageSize":   minPageSize,
	}
	list, _, expanded, err := c.postList(ctx, "/api/v1/search/users", body)
	if err != nil {
		return nil, err
	}
	return matchRoleNames(roleIDs, expanded, list), nil
}

func (c *Client) getUserAccess(ctx context.Context, _ *mcp.CallToolRequest, in GetUserAccessInput) (*mcp.CallToolResult, UserAccess, error) {
	var zero UserAccess
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, zero, c.scrub(err)
	}
	raw, err := c.getRaw(ctx, "/api/v1/users/"+url.PathEscape(in.UserID), nil)
	if err != nil {
		return nil, zero, err
	}
	obj, err := decodeObject(raw)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	view := asMap(obj["userView"])
	if view == nil {
		view = obj
	}
	user := userFromItem(view)
	if user.ID == "" {
		user.ID = in.UserID
	}

	accBody := map[string]any{
		"userIds":    []string{in.UserID},
		"pageSize":   accessCap,
		"expandMask": map[string]any{"paths": []string{"last_usage"}},
	}
	accList, accNext, _, err := c.postList(ctx, "/api/v1/search/app_users", accBody)
	if err != nil {
		return nil, zero, err
	}
	grantBody := map[string]any{
		"userId":   in.UserID,
		"pageSize": accessCap,
	}
	grantList, grantNext, _, err := c.postList(ctx, "/api/v1/search/grants", grantBody)
	if err != nil {
		return nil, zero, err
	}

	accounts := make([]AccountItem, 0, len(accList))
	for _, item := range accList {
		accounts = append(accounts, accountFromItem(item))
	}
	grants := make([]GrantItem, 0, len(grantList))
	for _, item := range grantList {
		grants = append(grants, grantFromItem(item))
	}
	truncA := accNext != "" || len(accounts) > accessCap
	truncG := grantNext != "" || len(grants) > accessCap
	if len(accounts) > accessCap {
		accounts = accounts[:accessCap]
	}
	if len(grants) > accessCap {
		grants = grants[:accessCap]
	}
	return nil, UserAccess{
		ID:                user.ID,
		DisplayName:       user.DisplayName,
		Email:             user.Email,
		Username:          user.Username,
		Status:            user.Status,
		Type:              user.Type,
		Department:        user.Department,
		JobTitle:          user.JobTitle,
		RoleIDs:           roleIDsOf(view),
		Accounts:          accounts,
		TruncatedAccounts: truncA,
		Grants:            grants,
		TruncatedGrants:   truncG,
	}, nil
}

func (c *Client) listApps(ctx context.Context, _ *mcp.CallToolRequest, in ListAppsInput) (*mcp.CallToolResult, idmcp.Page[AppItem], error) {
	var zero idmcp.Page[AppItem]
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	body := searchBody(clampPageSize(in.Limit), token)
	setBody(body, "query", in.Query)
	list, next, _, err := c.postList(ctx, "/api/v1/search/apps", body)
	if err != nil {
		return nil, zero, err
	}
	items := make([]AppItem, 0, len(list))
	for _, item := range list {
		items = append(items, appFromItem(item))
	}
	return nil, pageOf(items, next), nil
}

func (c *Client) listAppUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListAppUsersInput) (*mcp.CallToolResult, idmcp.Page[AccountItem], error) {
	var zero idmcp.Page[AccountItem]
	if err := idmcp.Require("app_id", in.AppID); err != nil {
		return nil, zero, c.scrub(err)
	}
	if err := oneOf("status", in.Status, "STATUS_ENABLED", "STATUS_DISABLED", "STATUS_DELETED"); err != nil {
		return nil, zero, c.scrub(err)
	}
	appUserType, err := canonicalAppUserType(in.Type)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	body := searchBody(clampPageSize(in.Limit), token)
	body["appId"] = in.AppID
	setBody(body, "query", in.Query)
	if in.Status != "" {
		body["appUserStatuses"] = []string{in.Status}
	}
	if appUserType != "" {
		body["appUserTypes"] = []string{appUserType}
	}
	list, next, _, err := c.postList(ctx, "/api/v1/search/app_users", body)
	if err != nil {
		return nil, zero, err
	}
	items := make([]AccountItem, 0, len(list))
	for _, item := range list {
		items = append(items, accountFromItem(item))
	}
	return nil, pageOf(items, next), nil
}

func canonicalAppUserType(v string) (string, error) {
	switch v {
	case "", "APP_USER_TYPE_USER", "APP_USER_TYPE_SERVICE_ACCOUNT", "APP_USER_TYPE_SYSTEM_ACCOUNT":
		return v, nil
	case "SERVICE_ACCOUNT":
		return "APP_USER_TYPE_SERVICE_ACCOUNT", nil
	case "SYSTEM_ACCOUNT":
		return "APP_USER_TYPE_SYSTEM_ACCOUNT", nil
	default:
		return "", oneOf("type", v, "APP_USER_TYPE_USER", "APP_USER_TYPE_SERVICE_ACCOUNT", "APP_USER_TYPE_SYSTEM_ACCOUNT", "SERVICE_ACCOUNT", "SYSTEM_ACCOUNT")
	}
}

func (c *Client) listEntitlements(ctx context.Context, _ *mcp.CallToolRequest, in ListEntitlementsInput) (*mcp.CallToolResult, idmcp.Page[EntitlementItem], error) {
	var zero idmcp.Page[EntitlementItem]
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	body := searchBody(clampPageSize(in.Limit), token)
	setBody(body, "query", in.Query)
	if in.AppID != "" {
		body["appIds"] = []string{in.AppID}
	}
	list, next, _, err := c.postList(ctx, "/api/v1/search/entitlements", body)
	if err != nil {
		return nil, zero, err
	}
	items := make([]EntitlementItem, 0, len(list))
	for _, item := range list {
		items = append(items, entitlementFromItem(item))
	}
	return nil, pageOf(items, next), nil
}

func (c *Client) listUncorrelatedAccounts(ctx context.Context, _ *mcp.CallToolRequest, in ListUncorrelatedAccountsInput) (*mcp.CallToolResult, idmcp.Page[AccountItem], error) {
	var zero idmcp.Page[AccountItem]
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	body := searchBody(clampPageSize(in.Limit), token)
	body["withoutResponsibleParty"] = true
	setBody(body, "appId", in.AppID)
	setBody(body, "query", in.Query)
	list, next, _, err := c.postList(ctx, "/api/v1/search/app_users", body)
	if err != nil {
		return nil, zero, err
	}
	items := make([]AccountItem, 0, len(list))
	for _, item := range list {
		items = append(items, accountFromItem(item))
	}
	return nil, pageOf(items, next), nil
}

func (c *Client) findStaleAccounts(ctx context.Context, _ *mcp.CallToolRequest, in FindStaleAccountsInput) (*mcp.CallToolResult, StalePage, error) {
	var zero StalePage
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	days := in.InactiveDays
	if days <= 0 {
		days = 90
	}
	want := in.Limit
	if want <= 0 {
		want = defaultPageSize
	}
	if want > staleScanCap {
		want = staleScanCap
	}
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	items := make([]StaleAccount, 0)
	scanned := 0
	next := ""
	for scanned < staleScanCap && len(items) < want {
		// A short remainder cannot finish another page. Resume it on a fresh budget.
		if token != "" && staleScanCap-scanned < stalePageSize {
			return nil, StalePage{Items: items, Next: token, Truncated: true, Scanned: scanned}, nil
		}
		sent := token
		body := map[string]any{
			"pageSize":   stalePageSize,
			"expandMask": map[string]any{"paths": []string{"last_usage"}},
		}
		if token != "" {
			body["pageToken"] = token
		}
		setBody(body, "appId", in.AppID)
		setBody(body, "query", in.Query)
		list, pageNext, _, err := c.postList(ctx, "/api/v1/search/app_users", body)
		if err != nil {
			return nil, zero, err
		}
		room := staleScanCap - scanned
		inspect := list
		clipped := false
		if len(list) > room {
			inspect = list[:room]
			clipped = true
		}
		scanned += len(inspect)
		leftover := false
		for _, item := range inspect {
			acc := accountFromItem(item)
			ts, missing := usageOf(item)
			reasons := staleReasons(acc.Status, ts, missing, cutoff, days)
			if len(reasons) == 0 {
				continue
			}
			if len(items) >= want {
				leftover = true
				continue
			}
			items = append(items, StaleAccount{
				AppID:          acc.AppID,
				ID:             acc.ID,
				DisplayName:    acc.DisplayName,
				Email:          acc.Email,
				Type:           acc.Type,
				Status:         acc.Status,
				IdentityUserID: acc.IdentityUserID,
				LastUsage:      ts,
				Reasons:        reasons,
			})
		}
		if clipped {
			// The page token cannot skip already-seen rows. Repeat the token that fetched this page.
			return nil, StalePage{Items: items, Next: sent, Truncated: true, Scanned: scanned}, nil
		}
		if leftover {
			return nil, StalePage{Items: items, Truncated: true, Scanned: scanned}, nil
		}
		if len(list) == 0 && pageNext != "" {
			return nil, StalePage{Items: items, Next: pageNext, Truncated: true, Scanned: scanned}, nil
		}
		next = pageNext
		if next == "" {
			break
		}
		token = next
	}
	return nil, StalePage{Items: items, Next: next, Truncated: next != "", Scanned: scanned}, nil
}

func (c *Client) listAccessReviews(ctx context.Context, _ *mcp.CallToolRequest, in ListAccessReviewsInput) (*mcp.CallToolResult, idmcp.Page[AccessReviewItem], error) {
	var zero idmcp.Page[AccessReviewItem]
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	q := url.Values{}
	q.Set("page_size", strconv.Itoa(clampPageSize(in.Limit)))
	if token != "" {
		q.Set("page_token", token)
	}
	raw, err := c.getRaw(ctx, "/api/v1/access_reviews", q)
	if err != nil {
		return nil, zero, err
	}
	list, next, _, err := decodeList(raw)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	items := make([]AccessReviewItem, 0, len(list))
	for _, item := range list {
		items = append(items, reviewFromItem(item))
	}
	return nil, pageOf(items, next), nil
}

func (c *Client) listTasks(ctx context.Context, _ *mcp.CallToolRequest, in ListTasksInput) (*mcp.CallToolResult, idmcp.Page[TaskItem], error) {
	var zero idmcp.Page[TaskItem]
	if err := oneOf("state", in.State, "TASK_STATE_OPEN", "TASK_STATE_CLOSED"); err != nil {
		return nil, zero, c.scrub(err)
	}
	token, err := cursor(in.PageToken)
	if err != nil {
		return nil, zero, c.scrub(err)
	}
	body := searchBody(taskPageSize(in.Limit), token)
	setBody(body, "query", in.Query)
	setBody(body, "createdAfter", in.CreatedAfter)
	setBody(body, "createdBefore", in.CreatedBefore)
	if in.UserID != "" {
		body["subjectIds"] = []string{in.UserID}
	}
	if in.AppID != "" {
		body["applicationIds"] = []string{in.AppID}
	}
	if in.AccessReviewID != "" {
		body["accessReviewIds"] = []string{in.AccessReviewID}
	}
	if in.State != "" {
		body["taskStates"] = []string{in.State}
	}
	list, next, _, err := c.postList(ctx, "/api/v1/search/tasks", body)
	if err != nil {
		return nil, zero, err
	}
	items := make([]TaskItem, 0, len(list))
	for _, item := range list {
		items = append(items, taskFromItem(item))
	}
	return nil, pageOf(items, next), nil
}
