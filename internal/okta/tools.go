package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

type oktaUser struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	Created     string         `json:"created"`
	LastLogin   *string        `json:"lastLogin"`
	LastUpdated string         `json:"lastUpdated"`
	Profile     map[string]any `json:"profile"`
}

type oktaGroup struct {
	ID                    string         `json:"id"`
	Type                  string         `json:"type"`
	LastMembershipUpdated string         `json:"lastMembershipUpdated"`
	Profile               map[string]any `json:"profile"`
}

type oktaApp struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	SignOnMode string `json:"signOnMode"`
}

type oktaAppUser struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	LastUpdated string         `json:"lastUpdated"`
	Profile     map[string]any `json:"profile"`
}

type oktaLog struct {
	UUID           string `json:"uuid"`
	Published      string `json:"published"`
	EventType      string `json:"eventType"`
	DisplayMessage string `json:"displayMessage"`
	Actor          struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		AlternateID string `json:"alternateId"`
		Type        string `json:"type"`
	} `json:"actor"`
	Outcome struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	} `json:"outcome"`
	Target []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		DisplayName string `json:"displayName"`
		AlternateID string `json:"alternateId"`
	} `json:"target"`
}

func (s *Service) ListUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListUsersInput) (*mcp.CallToolResult, idmcp.Page[UserItem], error) {
	if in.Search != "" && in.Filter != "" {
		return nil, idmcp.Page[UserItem]{}, fmt.Errorf("search and filter are mutually exclusive")
	}
	q := url.Values{}
	setQuery(q, "search", in.Search)
	setQuery(q, "filter", in.Filter)
	setLimit(q, in.Limit)
	var raw []oktaUser
	hdr, err := s.getJSON(ctx, "/api/v1/users", in.After, q, &raw)
	if err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	items := make([]UserItem, 0, len(raw))
	for _, u := range raw {
		items = append(items, userItem(u))
	}
	return nil, pageOf(items, hdr), nil
}

func (s *Service) GetUser(ctx context.Context, _ *mcp.CallToolRequest, in GetUserInput) (*mcp.CallToolResult, UserDetail, error) {
	if err := idmcp.Require("id_or_login", in.IDOrLogin); err != nil {
		return nil, UserDetail{}, err
	}
	var u oktaUser
	_, err := s.client.GetJSON(ctx, "/api/v1/users/"+url.PathEscape(in.IDOrLogin), nil, &u)
	if err != nil {
		return nil, UserDetail{}, err
	}
	item := userItem(u)
	return nil, UserDetail{
		ID:          item.ID,
		Login:       item.Login,
		Email:       item.Email,
		Status:      item.Status,
		Created:     item.Created,
		LastLogin:   item.LastLogin,
		LastUpdated: item.LastUpdated,
		Profile:     pickProfile(u.Profile),
	}, nil
}

func (s *Service) ListUserGroups(ctx context.Context, _ *mcp.CallToolRequest, in ListUserGroupsInput) (*mcp.CallToolResult, idmcp.Page[GroupItem], error) {
	if err := idmcp.Require("user_id", in.UserID); err != nil {
		return nil, idmcp.Page[GroupItem]{}, err
	}
	q := url.Values{}
	setLimit(q, in.Limit)
	var raw []oktaGroup
	hdr, err := s.getJSON(ctx, "/api/v1/users/"+url.PathEscape(in.UserID)+"/groups", in.After, q, &raw)
	if err != nil {
		return nil, idmcp.Page[GroupItem]{}, err
	}
	return nil, pageOf(mapGroups(raw), hdr), nil
}

func (s *Service) ListGroups(ctx context.Context, _ *mcp.CallToolRequest, in ListGroupsInput) (*mcp.CallToolResult, idmcp.Page[GroupItem], error) {
	q := url.Values{}
	setQuery(q, "q", in.Q)
	setQuery(q, "filter", in.Filter)
	setLimit(q, in.Limit)
	var raw []oktaGroup
	hdr, err := s.getJSON(ctx, "/api/v1/groups", in.After, q, &raw)
	if err != nil {
		return nil, idmcp.Page[GroupItem]{}, err
	}
	return nil, pageOf(mapGroups(raw), hdr), nil
}

func (s *Service) ListGroupUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListGroupUsersInput) (*mcp.CallToolResult, idmcp.Page[UserItem], error) {
	if err := idmcp.Require("group_id", in.GroupID); err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	q := url.Values{}
	setLimit(q, in.Limit)
	var raw []oktaUser
	hdr, err := s.getJSON(ctx, "/api/v1/groups/"+url.PathEscape(in.GroupID)+"/users", in.After, q, &raw)
	if err != nil {
		return nil, idmcp.Page[UserItem]{}, err
	}
	items := make([]UserItem, 0, len(raw))
	for _, u := range raw {
		items = append(items, userItem(u))
	}
	return nil, pageOf(items, hdr), nil
}

func (s *Service) ListApps(ctx context.Context, _ *mcp.CallToolRequest, in ListAppsInput) (*mcp.CallToolResult, idmcp.Page[AppItem], error) {
	q := url.Values{}
	setQuery(q, "q", in.Q)
	setQuery(q, "filter", in.Filter)
	setLimit(q, in.Limit)
	var raw []oktaApp
	hdr, err := s.getJSON(ctx, "/api/v1/apps", in.After, q, &raw)
	if err != nil {
		return nil, idmcp.Page[AppItem]{}, err
	}
	items := make([]AppItem, 0, len(raw))
	for _, a := range raw {
		items = append(items, AppItem{
			ID:         a.ID,
			Name:       a.Name,
			Label:      a.Label,
			Status:     a.Status,
			SignOnMode: a.SignOnMode,
		})
	}
	return nil, pageOf(items, hdr), nil
}

func (s *Service) ListAppUsers(ctx context.Context, _ *mcp.CallToolRequest, in ListAppUsersInput) (*mcp.CallToolResult, idmcp.Page[AppUserItem], error) {
	if err := idmcp.Require("app_id", in.AppID); err != nil {
		return nil, idmcp.Page[AppUserItem]{}, err
	}
	q := url.Values{}
	setLimit(q, in.Limit)
	var raw []oktaAppUser
	hdr, err := s.getJSON(ctx, "/api/v1/apps/"+url.PathEscape(in.AppID)+"/users", in.After, q, &raw)
	if err != nil {
		return nil, idmcp.Page[AppUserItem]{}, err
	}
	items := make([]AppUserItem, 0, len(raw))
	for _, u := range raw {
		items = append(items, AppUserItem{
			ID:          u.ID,
			Status:      u.Status,
			LastUpdated: u.LastUpdated,
			Email:       profileString(u.Profile, "email"),
		})
	}
	return nil, pageOf(items, hdr), nil
}

func (s *Service) ListAdmins(ctx context.Context, _ *mcp.CallToolRequest, in ListAdminsInput) (*mcp.CallToolResult, idmcp.Page[AdminItem], error) {
	q := url.Values{}
	setLimit(q, in.Limit)
	after, err := idmcp.OpaqueCursor(in.After, "after")
	if err != nil {
		return nil, idmcp.Page[AdminItem]{}, err
	}
	if after != "" {
		q.Set("after", after)
	}
	body, hdr, err := s.client.Get(ctx, "/api/v1/iam/assignees/users", q)
	if err != nil {
		if sc := idmcp.StatusOf(err); sc == 401 || sc == 403 {
			return nil, idmcp.Page[AdminItem]{}, fmt.Errorf("IAM assignees API requires okta.roles.read / an admin token: %w", err)
		}
		return nil, idmcp.Page[AdminItem]{}, err
	}
	items, err := parseAdmins(body)
	if err != nil {
		return nil, idmcp.Page[AdminItem]{}, err
	}
	items, err = s.enrichAdmins(ctx, items)
	if err != nil {
		return nil, idmcp.Page[AdminItem]{}, err
	}
	next := adminPageNext(body)
	if next == "" {
		next = nextCursor(hdr)
	}
	if items == nil {
		items = []AdminItem{}
	}
	return nil, idmcp.Page[AdminItem]{Items: items, Next: next, Truncated: next != ""}, nil
}

func (s *Service) FindStaleUsers(ctx context.Context, _ *mcp.CallToolRequest, in FindStaleUsersInput) (*mcp.CallToolResult, StalePage, error) {
	days := in.InactiveDays
	if days <= 0 {
		days = 90
	}
	want := idmcp.ClampLimit(in.Limit)
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	after, err := idmcp.OpaqueCursor(in.After, "after")
	if err != nil {
		return nil, StalePage{}, err
	}
	items := make([]StaleUser, 0)
	scanned := 0
	var hdr http.Header
	for page := 0; page < idmcp.MaxStalePages && len(items) < want; page++ {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(idmcp.DefaultLimit))
		q.Set("search", `status eq "ACTIVE" or status eq "STAGED" or status eq "PROVISIONED" or status eq "PASSWORD_EXPIRED" or status eq "SUSPENDED" or status eq "LOCKED_OUT" or status eq "RECOVERY"`)
		if after != "" {
			q.Set("after", after)
		}
		var raw []oktaUser
		hdr, err = s.client.GetJSON(ctx, "/api/v1/users", q, &raw)
		if err != nil {
			return nil, StalePage{}, err
		}
		scanned += len(raw)
		leftover := false
		for _, u := range raw {
			last := deref(u.LastLogin)
			reason, stale := staleReason(u.Status, last, cutoff, days)
			if !stale {
				continue
			}
			if len(items) >= want {
				leftover = true
				continue
			}
			items = append(items, StaleUser{
				ID:        u.ID,
				Login:     profileString(u.Profile, "login"),
				Status:    u.Status,
				LastLogin: last,
				Reason:    reason,
			})
		}
		after = nextCursor(hdr)
		if leftover {
			return nil, StalePage{Items: items, Truncated: true, Scanned: scanned}, nil
		}
		if after == "" || len(raw) == 0 {
			break
		}
	}
	next := nextCursor(hdr)
	return nil, StalePage{
		Items:     items,
		Next:      next,
		Truncated: next != "",
		Scanned:   scanned,
	}, nil
}

func (s *Service) ListLogs(ctx context.Context, _ *mcp.CallToolRequest, in ListLogsInput) (*mcp.CallToolResult, idmcp.Page[LogItem], error) {
	q := url.Values{}
	setQuery(q, "filter", in.Filter)
	setQuery(q, "q", in.Q)
	n := idmcp.ClampLimit(in.Limit)
	if n > 100 {
		n = 100
	}
	q.Set("limit", strconv.Itoa(n))
	after, err := idmcp.OpaqueCursor(in.After, "after")
	if err != nil {
		return nil, idmcp.Page[LogItem]{}, err
	}
	// Okta System Log: since and after are mutually exclusive.
	if after != "" {
		q.Set("after", after)
	} else {
		setQuery(q, "since", in.Since)
		setQuery(q, "until", in.Until)
	}
	var raw []oktaLog
	hdr, err := s.client.GetJSON(ctx, "/api/v1/logs", q, &raw)
	if err != nil {
		return nil, idmcp.Page[LogItem]{}, err
	}
	items := make([]LogItem, 0, len(raw))
	for _, ev := range raw {
		items = append(items, LogItem{
			UUID:           ev.UUID,
			Published:      ev.Published,
			Actor:          formatActor(ev.Actor.DisplayName, ev.Actor.AlternateID, ev.Actor.ID),
			EventType:      ev.EventType,
			DisplayMessage: ev.DisplayMessage,
			Outcome:        formatOutcome(ev.Outcome.Result, ev.Outcome.Reason),
			Target:         formatTargets(ev.Target),
		})
	}
	return nil, pageOf(items, hdr), nil
}

func (s *Service) getJSON(ctx context.Context, path, after string, q url.Values, dest any) (http.Header, error) {
	cur, err := idmcp.OpaqueCursor(after, "after")
	if err != nil {
		return nil, err
	}
	if cur != "" {
		if q == nil {
			q = url.Values{}
		}
		q.Set("after", cur)
	}
	return s.client.GetJSON(ctx, path, q, dest)
}

func setQuery(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func setLimit(q url.Values, n int) {
	q.Set("limit", strconv.Itoa(idmcp.ClampLimit(n)))
}

func nextCursor(hdr http.Header) string {
	next := idmcp.LinkHeader(hdr, "next")
	if next == "" {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil {
		return next
	}
	if after := u.Query().Get("after"); after != "" {
		return after
	}
	return next
}

func pageOf[T any](items []T, hdr http.Header) idmcp.Page[T] {
	if items == nil {
		items = []T{}
	}
	next := nextCursor(hdr)
	return idmcp.Page[T]{Items: items, Next: next, Truncated: next != ""}
}

func userItem(u oktaUser) UserItem {
	return UserItem{
		ID:          u.ID,
		Login:       profileString(u.Profile, "login"),
		Email:       profileString(u.Profile, "email"),
		Status:      u.Status,
		Created:     u.Created,
		LastLogin:   deref(u.LastLogin),
		LastUpdated: u.LastUpdated,
	}
}

func mapGroups(raw []oktaGroup) []GroupItem {
	items := make([]GroupItem, 0, len(raw))
	for _, g := range raw {
		items = append(items, GroupItem{
			ID:                    g.ID,
			Name:                  profileString(g.Profile, "name"),
			Type:                  g.Type,
			Description:           profileString(g.Profile, "description"),
			LastMembershipUpdated: g.LastMembershipUpdated,
		})
	}
	return items
}

func pickProfile(p map[string]any) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"firstName", "lastName", "department", "title", "employeeNumber"} {
		if s := profileString(p, k); s != "" {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func profileString(p map[string]any, key string) string {
	if p == nil {
		return ""
	}
	return asString(p[key])
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func staleReason(status, lastLogin string, cutoff time.Time, days int) (string, bool) {
	switch strings.ToUpper(status) {
	case "STAGED", "PROVISIONED", "PASSWORD_EXPIRED":
		return "non_active_status", true
	}
	if lastLogin == "" {
		return "no_login", true
	}
	t, err := time.Parse(time.RFC3339, lastLogin)
	if err != nil {
		return "unparsed_last_login", true
	}
	if t.Before(cutoff) {
		return fmt.Sprintf("login_older_than_%d_days", days), true
	}
	return "", false
}

func formatActor(displayName, alternateID, id string) string {
	switch {
	case displayName != "" && alternateID != "":
		return displayName + " (" + alternateID + ")"
	case displayName != "":
		return displayName
	case alternateID != "":
		return alternateID
	default:
		return id
	}
}

func formatOutcome(result, reason string) string {
	if reason != "" {
		return result + ": " + reason
	}
	return result
}

func formatTargets(targets []struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"displayName"`
	AlternateID string `json:"alternateId"`
}) string {
	parts := make([]string, 0, len(targets))
	for _, t := range targets {
		name := t.DisplayName
		if name == "" {
			name = t.AlternateID
		}
		if name == "" {
			name = t.ID
		}
		if t.Type != "" && name != "" {
			parts = append(parts, name+" ("+t.Type+")")
		} else if name != "" {
			parts = append(parts, name)
		} else if t.Type != "" {
			parts = append(parts, t.Type)
		}
	}
	return strings.Join(parts, ", ")
}

func parseAdmins(body []byte) ([]AdminItem, error) {
	var rows []json.RawMessage
	var wrapped struct {
		Value json.RawMessage `json:"value"`
		Users json.RawMessage `json:"users"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && (wrapped.Value != nil || wrapped.Users != nil) {
		raw := wrapped.Value
		if len(raw) == 0 {
			raw = wrapped.Users
		}
		trim := bytes.TrimSpace(raw)
		if len(trim) == 0 || string(trim) == "null" || string(trim) == "[]" {
			return []AdminItem{}, nil
		}
		if trim[0] != '[' {
			return nil, fmt.Errorf("IAM assignees payload: expected array or {value|users: [...]}")
		}
		if err := json.Unmarshal(trim, &rows); err != nil {
			return nil, fmt.Errorf("IAM assignees payload: unexpected array: %w", err)
		}
	} else if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("IAM assignees payload: expected array or {value|users: [...]}")
	}
	items := make([]AdminItem, 0, len(rows))
	for _, raw := range rows {
		if item, ok := adminFromRaw(raw); ok {
			items = append(items, item)
		}
	}
	if len(items) == 0 && len(rows) > 0 {
		return nil, fmt.Errorf("IAM assignees payload: no recognizable admin rows")
	}
	return items, nil
}

func adminPageNext(body []byte) string {
	var env struct {
		Links struct {
			Next struct {
				Href string `json:"href"`
			} `json:"next"`
		} `json:"_links"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	href := strings.TrimSpace(env.Links.Next.Href)
	if href == "" {
		return ""
	}
	cur, err := idmcp.OpaqueCursor(href, "after")
	if err != nil {
		return ""
	}
	return cur
}

func (s *Service) enrichAdmins(ctx context.Context, items []AdminItem) ([]AdminItem, error) {
	for i, item := range items {
		if item.ID == "" {
			continue
		}
		if item.Login == "" || item.Email == "" {
			var u oktaUser
			if _, err := s.client.GetJSON(ctx, "/api/v1/users/"+url.PathEscape(item.ID), nil, &u); err == nil {
				if item.Login == "" {
					item.Login = profileString(u.Profile, "login")
				}
				if item.Email == "" {
					item.Email = profileString(u.Profile, "email")
				}
			}
		}
		if len(item.RoleLabels) == 0 {
			var roles []struct {
				Label string `json:"label"`
				Type  string `json:"type"`
				Name  string `json:"name"`
			}
			if _, err := s.client.GetJSON(ctx, "/api/v1/users/"+url.PathEscape(item.ID)+"/roles", nil, &roles); err == nil {
				labels := make([]string, 0, len(roles))
				for _, r := range roles {
					switch {
					case r.Label != "":
						labels = append(labels, r.Label)
					case r.Type != "":
						labels = append(labels, r.Type)
					case r.Name != "":
						labels = append(labels, r.Name)
					}
				}
				item.RoleLabels = labels
			}
		}
		if item.RoleLabels == nil {
			item.RoleLabels = []string{}
		}
		items[i] = item
	}
	return items, nil
}

func adminFromRaw(raw json.RawMessage) (AdminItem, bool) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return AdminItem{}, false
	}
	id := asString(m["id"])
	email := asString(m["email"])
	login := asString(m["login"])
	labels := roleLabels(m["roles"])
	if u, ok := m["user"].(map[string]any); ok {
		if id == "" {
			id = asString(u["id"])
		}
		if email == "" {
			email = asString(u["email"])
		}
		if login == "" {
			login = asString(u["login"])
		}
		if p, ok := u["profile"].(map[string]any); ok {
			if email == "" {
				email = asString(p["email"])
			}
			if login == "" {
				login = asString(p["login"])
			}
		}
		if len(labels) == 0 {
			labels = roleLabels(u["roles"])
		}
	}
	if p, ok := m["profile"].(map[string]any); ok {
		if email == "" {
			email = asString(p["email"])
		}
		if login == "" {
			login = asString(p["login"])
		}
	}
	if len(labels) == 0 {
		if s := asString(m["label"]); s != "" {
			labels = []string{s}
		}
	}
	if id == "" && email == "" && login == "" {
		return AdminItem{}, false
	}
	if labels == nil {
		labels = []string{}
	}
	return AdminItem{ID: id, Email: email, Login: login, RoleLabels: labels}, true
}

func roleLabels(v any) []string {
	switch t := v.(type) {
	case string:
		if t != "" {
			return []string{t}
		}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			switch r := x.(type) {
			case string:
				if r != "" {
					out = append(out, r)
				}
			case map[string]any:
				if s := asString(r["label"]); s != "" {
					out = append(out, s)
				} else if s := asString(r["type"]); s != "" {
					out = append(out, s)
				} else if s := asString(r["name"]); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	return nil
}
