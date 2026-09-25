package c1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"
)

func unmarshal(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(dest)
}

func decodeObject(raw []byte) (map[string]any, error) {
	var m map[string]any
	if err := unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("decode c1 object: %w", err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func decodeList(raw []byte) ([]map[string]any, string, []any, error) {
	var env struct {
		List          json.RawMessage `json:"list"`
		NextPageToken json.RawMessage `json:"nextPageToken"`
		Expanded      json.RawMessage `json:"expanded"`
	}
	if err := unmarshal(raw, &env); err != nil {
		return nil, "", nil, fmt.Errorf("decode c1 response: %w", err)
	}
	var list []map[string]any
	if len(env.List) > 0 && string(env.List) != "null" {
		if err := unmarshal(env.List, &list); err != nil {
			return nil, "", nil, fmt.Errorf("decode c1 list: %w", err)
		}
	}
	if list == nil {
		list = []map[string]any{}
	}
	return list, rawString(env.NextPageToken), decodeExpanded(env.Expanded), nil
}

func decodeExpanded(raw json.RawMessage) []any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var arr []any
	if unmarshal(raw, &arr) == nil {
		return arr
	}
	var one any
	if unmarshal(raw, &one) == nil && one != nil {
		return []any{one}
	}
	return nil
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func asBool(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			if s := asString(el); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), t...)
	default:
		if s := asString(v); s != "" {
			return []string{s}
		}
		return nil
	}
}

func nestedOrSelf(item map[string]any, key string) map[string]any {
	if m := asMap(item[key]); m != nil {
		return m
	}
	return item
}

func userFromItem(item map[string]any) UserItem {
	src := nestedOrSelf(item, "user")
	return UserItem{
		ID:          asString(src["id"]),
		DisplayName: asString(src["displayName"]),
		Email:       asString(src["email"]),
		Username:    asString(src["username"]),
		Status:      asString(src["status"]),
		Type:        asString(src["type"]),
		Department:  asString(src["department"]),
		JobTitle:    asString(src["jobTitle"]),
	}
}

func roleIDsOf(item map[string]any) []string {
	src := nestedOrSelf(item, "user")
	ids := stringList(src["roleIds"])
	if ids == nil {
		return []string{}
	}
	return ids
}

func nestedStatus(v any) string {
	if m := asMap(v); m != nil {
		return asString(m["status"])
	}
	return asString(v)
}

func accountFromItem(item map[string]any) AccountItem {
	src := nestedOrSelf(item, "appUser")
	typ := asString(src["appUserType"])
	if typ == "" {
		typ = asString(src["type"])
	}
	acc := AccountItem{
		AppID:          asString(src["appId"]),
		ID:             asString(src["id"]),
		DisplayName:    asString(src["displayName"]),
		Email:          asString(src["email"]),
		Type:           typ,
		Status:         nestedStatus(src["status"]),
		IdentityUserID: asString(src["identityUserId"]),
	}
	if ts, _ := usageOf(item); ts != "" {
		acc.LastUsage = ts
	}
	return acc
}

func grantFromItem(item map[string]any) GrantItem {
	src := nestedOrSelf(item, "appEntitlementUserBinding")
	name := ""
	if ae := asMap(item["appEntitlement"]); ae != nil {
		name = asString(ae["displayName"])
	}
	if name == "" {
		if ent := asMap(item["entitlement"]); ent != nil {
			name = asString(ent["displayName"])
		}
	}
	return GrantItem{
		AppID:         asString(src["appId"]),
		EntitlementID: asString(src["appEntitlementId"]),
		DisplayName:   name,
	}
}

func appFromItem(item map[string]any) AppItem {
	src := nestedOrSelf(item, "app")
	return AppItem{
		ID:          asString(src["id"]),
		DisplayName: asString(src["displayName"]),
		Description: asString(src["description"]),
		IsDirectory: asBool(src["isDirectory"]),
	}
}

func entitlementFromItem(item map[string]any) EntitlementItem {
	src := item
	if m := asMap(item["appEntitlement"]); m != nil {
		src = m
	} else if m := asMap(item["entitlement"]); m != nil {
		src = m
	}
	return EntitlementItem{
		ID:          asString(src["id"]),
		DisplayName: asString(src["displayName"]),
		AppID:       asString(src["appId"]),
		Alias:       asString(src["alias"]),
	}
}

func reviewFromItem(item map[string]any) AccessReviewItem {
	src := nestedOrSelf(item, "accessReview")
	return AccessReviewItem{
		ID:          asString(src["id"]),
		DisplayName: asString(src["displayName"]),
		State:       asString(src["state"]),
		CreatedAt:   asString(src["createdAt"]),
	}
}

func taskFromItem(item map[string]any) TaskItem {
	src := nestedOrSelf(item, "task")
	kind, outcome, appID := taskKind(src["type"])
	return TaskItem{
		ID:          asString(src["id"]),
		NumericID:   asString(src["numericId"]),
		DisplayName: asString(src["displayName"]),
		State:       asString(src["state"]),
		Type:        kind,
		Outcome:     outcome,
		CreatedAt:   asString(src["createdAt"]),
		UserID:      asString(src["userId"]),
		AppID:       appID,
	}
}

func taskKind(v any) (kind, outcome, appID string) {
	m := asMap(v)
	if m == nil {
		return "", "", ""
	}
	for _, k := range []string{"grant", "revoke", "certify", "offboarding", "action", "finding"} {
		child, ok := m[k]
		if !ok || child == nil {
			continue
		}
		kind = k
		cm := asMap(child)
		if cm == nil {
			return kind, "", ""
		}
		outcome = asString(cm["outcome"])
		if k == "grant" || k == "revoke" || k == "certify" {
			appID = asString(cm["appId"])
		}
		return kind, outcome, appID
	}
	return "", "", ""
}

// usageOf reports an RFC3339 timestamp from the expanded object.
// missing is true when no lastUsedAt, lastLogin, or accessedAt key is present.
// A present key that is not RFC3339 yields ts "" and missing false (unknown; do not invent a date).
func usageOf(item map[string]any) (ts string, missing bool) {
	v, ok := expandValue(item)
	if !ok || !hasTimeKey(v) {
		return "", true
	}
	return firstRFC3339(v), false
}

func expandValue(item map[string]any) (any, bool) {
	if v, ok := firstValue(item, "expanded", "lastUsage", "last_usage"); ok {
		return v, true
	}
	if au := asMap(item["appUser"]); au != nil {
		if v, ok := firstValue(au, "expanded", "lastUsage", "last_usage"); ok {
			return v, true
		}
	}
	return nil, false
}

func firstValue(m map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		v, ok := m[k]
		if ok && v != nil {
			return v, true
		}
	}
	return nil, false
}

func hasTimeKey(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"lastUsedAt", "lastLogin", "accessedAt"} {
			if val, ok := t[k]; ok && val != nil {
				return true
			}
		}
		for _, child := range t {
			if hasTimeKey(child) {
				return true
			}
		}
	case []any:
		for _, el := range t {
			if hasTimeKey(el) {
				return true
			}
		}
	}
	return false
}

func firstRFC3339(v any) string {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"lastUsedAt", "lastLogin", "accessedAt"} {
			if s := rfc3339String(t[k]); s != "" {
				return s
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			if k == "lastUsedAt" || k == "lastLogin" || k == "accessedAt" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if s := firstRFC3339(t[k]); s != "" {
				return s
			}
		}
	case []any:
		for _, el := range t {
			if s := firstRFC3339(el); s != "" {
				return s
			}
		}
	}
	return ""
}

func rfc3339String(v any) string {
	s, ok := v.(string)
	if !ok || s == "" {
		return ""
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return s
	}
	return ""
}

type nameRef struct {
	ID   string
	Name string
}

func matchRoleNames(roleIDs []string, expanded []any, items []map[string]any) []string {
	var found []nameRef
	for _, obj := range expanded {
		found = collectNames(obj, found)
	}
	for _, item := range items {
		if v, ok := item["expanded"]; ok {
			found = collectNames(v, found)
		}
	}
	if len(found) == 0 {
		return nil
	}
	if len(roleIDs) > 0 {
		byID := make(map[string]string, len(found))
		for _, f := range found {
			if f.ID != "" {
				if _, ok := byID[f.ID]; !ok {
					byID[f.ID] = f.Name
				}
			}
		}
		if len(byID) > 0 {
			names := make([]string, 0, len(roleIDs))
			for _, id := range roleIDs {
				if n, ok := byID[id]; ok {
					names = append(names, n)
				}
			}
			if len(names) > 0 {
				return names
			}
		}
	}
	names := make([]string, 0, len(found))
	for _, f := range found {
		if f.Name != "" {
			names = append(names, f.Name)
		}
	}
	return names
}

func collectNames(v any, out []nameRef) []nameRef {
	switch t := v.(type) {
	case []any:
		for _, el := range t {
			out = collectNames(el, out)
		}
	case map[string]any:
		if name := asString(t["displayName"]); name != "" {
			return append(out, nameRef{ID: asString(t["id"]), Name: name})
		}
		for _, k := range []string{"role", "user", "app"} {
			if child := asMap(t[k]); child != nil {
				out = collectNames(child, out)
			}
		}
	}
	return out
}

func staleReasons(status, lastUsage string, missing bool, cutoff time.Time, days int) []string {
	var reasons []string
	switch status {
	case "STATUS_DISABLED", "STATUS_DELETED":
		reasons = append(reasons, status)
	}
	if missing {
		reasons = append(reasons, "no_usage")
		return reasons
	}
	if lastUsage == "" {
		return reasons
	}
	ts, err := time.Parse(time.RFC3339Nano, lastUsage)
	if err == nil && ts.Before(cutoff) {
		reasons = append(reasons, fmt.Sprintf("usage_older_than_%d_days", days))
	}
	return reasons
}
