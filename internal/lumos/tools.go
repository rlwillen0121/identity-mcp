package lumos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const lumosMaxSize = 100
const userAccessAccountCap = 50
const accessReviewAppCap = 20
const staleScanCap = 500

type lumosPage[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
	Page  int `json:"page"`
	Size  int `json:"size"`
	Pages int `json:"pages"`
}

type rawUser struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Status     string `json:"status"`
}

type rawApp struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	UserFriendlyLabel string `json:"user_friendly_label"`
	Status            string `json:"status"`
	Category          string `json:"category"`
}

type rawGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type rawAccount struct {
	ID               string          `json:"id"`
	UniqueIdentifier string          `json:"unique_identifier"`
	Status           string          `json:"status"`
	LastLogin        string          `json:"last_login"`
	LastActivity     string          `json:"last_activity"`
	LastAccessedAt   string          `json:"last_accessed_at"`
	AppID            string          `json:"app_id"`
	AppName          string          `json:"app_name"`
	App              json.RawMessage `json:"app"`
}

type rawReview struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	DeadlineAt  string `json:"deadline_at"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	Apps        []struct {
		DomainAppName string `json:"domain_app_name"`
	} `json:"apps"`
}

type rawActivityPage struct {
	Items  []rawActivity `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
	Links  struct {
		Next string `json:"next"`
	} `json:"links"`
}

type rawActivity struct {
	EventHash             string         `json:"event_hash"`
	EventType             string         `json:"event_type"`
	EventTypeUserFriendly string         `json:"event_type_user_friendly"`
	Outcome               string         `json:"outcome"`
	EventBeganAt          string         `json:"event_began_at"`
	Actor                 map[string]any `json:"actor"`
}

func (s *Service) ListUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListUsersInput) (*mcp.CallToolResult, idmcp.Page[UserItem], error) {
	q, page, err := pageQuery(in.Page, in.Limit)
	if err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	setQuery(q, "search_term", in.SearchTerm)
	if in.ExactMatch {
		q.Set("exact_match", "true")
	}
	var raw lumosPage[rawUser]
	if _, err := s.client.GetJSON(ctx, "/users", q, &raw); err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	items := make([]UserItem, 0, len(raw.Items))
	for _, u := range raw.Items {
		items = append(items, userItem(u))
	}
	return nil, pageOf(items, page, raw.Pages, len(raw.Items), raw.Size), nil
}

func (s *Service) GetUser(ctx context.Context, _ *mcp.CallToolRequest, in GetUserInput) (*mcp.CallToolResult, UserItem, error) {
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, UserItem{}, err
	}
	var u rawUser
	if _, err := s.client.GetJSON(ctx, "/users/"+url.PathEscape(in.UserID), nil, &u); err != nil {
		return nil, UserItem{}, err
	}
	return nil, userItem(u), nil
}

func (s *Service) GetUserAccess(ctx context.Context, _ *mcp.CallToolRequest, in GetUserAccessInput) (*mcp.CallToolResult, UserAccess, error) {
	var zero UserAccess
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, zero, err
	}
	var u rawUser
	if _, err := s.client.GetJSON(ctx, "/users/"+url.PathEscape(in.UserID), nil, &u); err != nil {
		return nil, zero, err
	}
	accounts, truncated, err := s.userAccounts(ctx, in.UserID, userAccessAccountCap)
	if err != nil {
		return nil, zero, err
	}
	roles, err := s.userRoles(ctx, in.UserID)
	if err != nil {
		return nil, zero, err
	}
	if accounts == nil {
		accounts = []AccountItem{}
	}
	if roles == nil {
		roles = []string{}
	}
	item := userItem(u)
	return nil, UserAccess{
		ID:                item.ID,
		Email:             item.Email,
		GivenName:         item.GivenName,
		FamilyName:        item.FamilyName,
		Status:            item.Status,
		Roles:             roles,
		Accounts:          accounts,
		TruncatedAccounts: truncated,
	}, nil
}

func (s *Service) ListApps(ctx context.Context, _ *mcp.CallToolRequest, in ListAppsInput) (*mcp.CallToolResult, idmcp.Page[AppItem], error) {
	q, page, err := pageQuery(in.Page, in.Limit)
	if err != nil {
		return nil, idmcp.Page[AppItem]{}, err
	}
	var raw lumosPage[rawApp]
	if _, err := s.client.GetJSON(ctx, "/apps", q, &raw); err != nil {
		return nil, idmcp.Page[AppItem]{}, err
	}
	items := make([]AppItem, 0, len(raw.Items))
	for _, a := range raw.Items {
		items = append(items, appItem(a))
	}
	return nil, pageOf(items, page, raw.Pages, len(raw.Items), raw.Size), nil
}

func (s *Service) ListAppAccounts(ctx context.Context, _ *mcp.CallToolRequest, in ListAppAccountsInput) (*mcp.CallToolResult, idmcp.Page[AccountItem], error) {
	if err := idmcp.Require("app_id", in.AppID); err != nil {
		return nil, idmcp.Page[AccountItem]{}, err
	}
	q, page, err := pageQuery(in.Page, in.Limit)
	if err != nil {
		return nil, idmcp.Page[AccountItem]{}, err
	}
	q.Set("app_id", in.AppID)
	setQuery(q, "status", in.Status)
	q.Set("expand", "app")
	var raw lumosPage[rawAccount]
	if _, err := s.client.GetJSON(ctx, "/accounts", q, &raw); err != nil {
		return nil, idmcp.Page[AccountItem]{}, err
	}
	items := make([]AccountItem, 0, len(raw.Items))
	for _, a := range raw.Items {
		items = append(items, accountItem(a))
	}
	return nil, pageOf(items, page, raw.Pages, len(raw.Items), raw.Size), nil
}

func (s *Service) ListGroups(ctx context.Context, _ *mcp.CallToolRequest, in ListGroupsInput) (*mcp.CallToolResult, idmcp.Page[GroupItem], error) {
	q, page, err := pageQuery(in.Page, in.Limit)
	if err != nil {
		return nil, idmcp.Page[GroupItem]{}, err
	}
	var raw lumosPage[rawGroup]
	if _, err := s.client.GetJSON(ctx, "/groups", q, &raw); err != nil {
		return nil, idmcp.Page[GroupItem]{}, err
	}
	items := make([]GroupItem, 0, len(raw.Items))
	for _, g := range raw.Items {
		items = append(items, GroupItem{ID: g.ID, Name: g.Name})
	}
	return nil, pageOf(items, page, raw.Pages, len(raw.Items), raw.Size), nil
}

func (s *Service) ListGroupMembers(ctx context.Context, _ *mcp.CallToolRequest, in ListGroupMembersInput) (*mcp.CallToolResult, idmcp.Page[UserItem], error) {
	if err := idmcp.Require("group_id", in.GroupID); err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	q, page, err := pageQuery(in.Page, in.Limit)
	if err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	var raw lumosPage[rawUser]
	if _, err := s.client.GetJSON(ctx, "/groups/"+url.PathEscape(in.GroupID)+"/users", q, &raw); err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	items := make([]UserItem, 0, len(raw.Items))
	for _, u := range raw.Items {
		items = append(items, userItem(u))
	}
	return nil, pageOf(items, page, raw.Pages, len(raw.Items), raw.Size), nil
}

func (s *Service) FindStaleAccounts(ctx context.Context, _ *mcp.CallToolRequest, in FindStaleAccountsInput) (*mcp.CallToolResult, StalePage, error) {
	days := in.InactiveDays
	if days <= 0 {
		days = 90
	}
	want := idmcp.ClampLimit(in.Limit)
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	page, err := idmcp.ParseIntCursor(in.Page)
	if err != nil {
		return nil, StalePage{}, err
	}
	if page == 0 {
		page = 1
	}
	items := make([]StaleAccount, 0)
	scanned := 0
	lastPage, lastPages, lastN, lastSz := page, 0, 0, idmcp.DefaultLimit
	for i := 0; i < idmcp.MaxStalePages && len(items) < want && scanned < staleScanCap; i++ {
		requested := strconv.Itoa(page)
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("size", strconv.Itoa(idmcp.DefaultLimit))
		q.Set("expand", "app")
		setQuery(q, "app_id", in.AppID)
		var raw lumosPage[rawAccount]
		if _, err := s.client.GetJSON(ctx, "/accounts", q, &raw); err != nil {
			return nil, StalePage{}, err
		}
		lastPage = page
		lastPages = raw.Pages
		lastN = len(raw.Items)
		lastSz = raw.Size
		if lastSz <= 0 {
			lastSz = idmcp.DefaultLimit
		}
		rows := raw.Items
		clipped := false
		if room := staleScanCap - scanned; len(rows) > room {
			rows = rows[:room]
			clipped = true
		}
		scanned += len(rows)
		leftover := false
		for _, a := range rows {
			acc := accountItem(a)
			reasons := staleReasons(acc.Status, acc.LastLogin, cutoff, days)
			if len(reasons) == 0 {
				continue
			}
			if len(items) >= want {
				leftover = true
				continue
			}
			items = append(items, StaleAccount{
				ID:               acc.ID,
				AppID:            acc.AppID,
				AppName:          acc.AppName,
				Status:           acc.Status,
				LastLogin:        acc.LastLogin,
				UniqueIdentifier: acc.UniqueIdentifier,
				Reasons:          reasons,
			})
		}
		if clipped {
			return nil, StalePage{Items: items, Next: requested, Truncated: true, Scanned: scanned}, nil
		}
		if leftover {
			return nil, StalePage{Items: items, Truncated: true, Scanned: scanned}, nil
		}
		nxt := nextPageCursor(lastPage, lastPages, lastN, lastSz)
		if nxt == "" || lastN == 0 {
			break
		}
		page, _ = strconv.Atoi(nxt)
	}
	next := nextPageCursor(lastPage, lastPages, lastN, lastSz)
	return nil, StalePage{
		Items:     items,
		Next:      next,
		Truncated: next != "",
		Scanned:   scanned,
	}, nil
}

func (s *Service) ListAccessReviews(ctx context.Context, _ *mcp.CallToolRequest, in ListAccessReviewsInput) (*mcp.CallToolResult, idmcp.Page[AccessReviewItem], error) {
	q, page, err := pageQuery(in.Page, in.Limit)
	if err != nil {
		return nil, idmcp.Page[AccessReviewItem]{}, err
	}
	var raw lumosPage[rawReview]
	if _, err := s.client.GetJSON(ctx, "/access_reviews", q, &raw); err != nil {
		return nil, idmcp.Page[AccessReviewItem]{}, err
	}
	items := make([]AccessReviewItem, 0, len(raw.Items))
	for _, r := range raw.Items {
		names := make([]string, 0, len(r.Apps))
		for _, a := range r.Apps {
			if a.DomainAppName == "" {
				continue
			}
			if len(names) >= accessReviewAppCap {
				break
			}
			names = append(names, a.DomainAppName)
		}
		items = append(items, AccessReviewItem{
			ID:          r.ID,
			Name:        r.Name,
			Status:      r.Status,
			DeadlineAt:  r.DeadlineAt,
			StartedAt:   r.StartedAt,
			CompletedAt: r.CompletedAt,
			AppNames:    names,
		})
	}
	return nil, pageOf(items, page, raw.Pages, len(raw.Items), raw.Size), nil
}

func (s *Service) ListActivityLogs(ctx context.Context, _ *mcp.CallToolRequest, in ListActivityLogsInput) (*mcp.CallToolResult, idmcp.Page[ActivityLogItem], error) {
	offset, err := idmcp.ParseIntCursor(in.Offset)
	if err != nil {
		return nil, idmcp.Page[ActivityLogItem]{}, err
	}
	limit := idmcp.ClampSize(in.Limit, lumosMaxSize)
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	setQuery(q, "since", in.Since)
	setQuery(q, "until", in.Until)
	var raw rawActivityPage
	if _, err := s.client.GetJSON(ctx, "/activity_logs", q, &raw); err != nil {
		return nil, idmcp.Page[ActivityLogItem]{}, err
	}
	items := make([]ActivityLogItem, 0, len(raw.Items))
	for _, ev := range raw.Items {
		items = append(items, ActivityLogItem{
			EventHash:             ev.EventHash,
			EventType:             ev.EventType,
			EventTypeUserFriendly: ev.EventTypeUserFriendly,
			Outcome:               ev.Outcome,
			EventBeganAt:          ev.EventBeganAt,
			ActorID:               asString(ev.Actor["id"]),
			ActorEmail:            asString(ev.Actor["email"]),
		})
	}
	if items == nil {
		items = []ActivityLogItem{}
	}
	next := idmcp.NextOffset(offset, len(items), limit)
	return nil, idmcp.Page[ActivityLogItem]{Items: items, Next: next, Truncated: next != ""}, nil
}

func (s *Service) userAccounts(ctx context.Context, userID string, capN int) ([]AccountItem, bool, error) {
	items := make([]AccountItem, 0)
	truncated := false
	page := 1
	size := capN
	if size > lumosMaxSize {
		size = lumosMaxSize
	}
	for len(items) < capN {
		q := url.Values{}
		q.Set("expand", "app")
		q.Set("page", strconv.Itoa(page))
		q.Set("size", strconv.Itoa(size))
		var raw lumosPage[rawAccount]
		if _, err := s.client.GetJSON(ctx, "/users/"+url.PathEscape(userID)+"/accounts", q, &raw); err != nil {
			return nil, false, err
		}
		for _, a := range raw.Items {
			if len(items) >= capN {
				truncated = true
				break
			}
			items = append(items, accountItem(a))
		}
		if truncated {
			break
		}
		next := nextPageCursor(page, raw.Pages, len(raw.Items), size)
		if next == "" {
			break
		}
		if len(items) >= capN {
			truncated = true
			break
		}
		page, _ = strconv.Atoi(next)
	}
	return items, truncated, nil
}

func (s *Service) userRoles(ctx context.Context, userID string) ([]string, error) {
	body, _, err := s.client.Get(ctx, "/users/"+url.PathEscape(userID)+"/roles", nil)
	if err != nil {
		return nil, err
	}
	return parseRoles(body), nil
}

func parseRoles(body []byte) []string {
	trim := strings.TrimSpace(string(body))
	if trim == "" || trim == "null" {
		return []string{}
	}
	var names []string
	if err := json.Unmarshal(body, &names); err == nil {
		return compactStrings(names)
	}
	var objs []map[string]any
	if err := json.Unmarshal(body, &objs); err == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if s := roleName(o); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var wrapped struct {
		Items json.RawMessage `json:"items"`
		Roles json.RawMessage `json:"roles"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil {
		raw := wrapped.Items
		if len(raw) == 0 {
			raw = wrapped.Roles
		}
		if len(raw) > 0 {
			return parseRoles(raw)
		}
	}
	return []string{}
}

func roleName(m map[string]any) string {
	for _, k := range []string{"name", "role", "label"} {
		if s := asString(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func pageQuery(cursor string, limit int) (url.Values, int, error) {
	page, err := idmcp.ParseIntCursor(cursor)
	if err != nil {
		return nil, 0, err
	}
	if page == 0 {
		page = 1
	}
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("size", strconv.Itoa(idmcp.ClampSize(limit, lumosMaxSize)))
	return q, page, nil
}

func nextPageCursor(page, pages, n, size int) string {
	if next := idmcp.NextPage(page, pages); next != "" {
		return next
	}
	if pages <= 0 && size > 0 && n == size {
		return strconv.Itoa(page + 1)
	}
	return ""
}

func pageOf[T any](items []T, page, pages, n, size int) idmcp.Page[T] {
	if items == nil {
		items = []T{}
	}
	next := nextPageCursor(page, pages, n, size)
	return idmcp.Page[T]{Items: items, Next: next, Truncated: next != ""}
}

func setQuery(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func userItem(u rawUser) UserItem {
	return UserItem{
		ID:         u.ID,
		Email:      u.Email,
		GivenName:  u.GivenName,
		FamilyName: u.FamilyName,
		Status:     u.Status,
	}
}

func appItem(a rawApp) AppItem {
	name := a.UserFriendlyLabel
	if name == "" {
		name = a.Name
	}
	return AppItem{ID: a.ID, Name: name, Status: a.Status, Category: a.Category}
}

func accountItem(a rawAccount) AccountItem {
	appID := a.AppID
	appName := a.AppName
	if len(a.App) > 0 {
		var nested struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			UserFriendlyLabel string `json:"user_friendly_label"`
		}
		if json.Unmarshal(a.App, &nested) == nil {
			if appID == "" {
				appID = nested.ID
			}
			if appName == "" {
				appName = nested.Name
			}
			if appName == "" {
				appName = nested.UserFriendlyLabel
			}
		}
	}
	last := a.LastLogin
	if last == "" {
		last = a.LastActivity
	}
	if last == "" {
		last = a.LastAccessedAt
	}
	return AccountItem{
		ID:               a.ID,
		AppID:            appID,
		AppName:          appName,
		Status:           a.Status,
		LastLogin:        last,
		UniqueIdentifier: a.UniqueIdentifier,
	}
}

func staleReasons(status, lastLogin string, cutoff time.Time, days int) []string {
	var reasons []string
	switch strings.ToUpper(status) {
	case "SUSPENDED", "ARCHIVED", "DEPROVISIONED", "ACCESS_REMOVED", "WAITING_MANUAL_REMOVAL":
		reasons = append(reasons, strings.ToUpper(status))
	}
	if lastLogin == "" {
		reasons = append(reasons, "no_login")
	} else if ts, ok := parseTime(lastLogin); ok && ts.Before(cutoff) {
		reasons = append(reasons, fmt.Sprintf("login_older_than_%d_days", days))
	}
	return reasons
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts, true
	}
	return time.Time{}, false
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
