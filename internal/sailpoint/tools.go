package sailpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rlwillen0121/identity-mcp/internal/idmcp"
)

const (
	nestedCap          = 50
	searchCap          = 50
	activityCap        = 100
	uncorrelatedSample = 50
	staleScanCap       = 500
	staleIdentityQuery = `attributes.cloudLifecycleState:inactive OR identityState:INACTIVE`
)

type rawIdentity struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Alias         string         `json:"alias"`
	Email         string         `json:"email"`
	IdentityState string         `json:"identityState"`
	Attributes    map[string]any `json:"attributes"`
}

type rawAccount struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	NativeIdentity string `json:"nativeIdentity"`
	Disabled       bool   `json:"disabled"`
	Uncorrelated   bool   `json:"uncorrelated"`
	SourceID       string `json:"sourceId"`
	SourceName     string `json:"sourceName"`
	IdentityID     string `json:"identityId"`
}

type rawSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Healthy *bool  `json:"healthy"`
	Status  string `json:"status"`
}

type rawActivity struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Created   string          `json:"created"`
	Requester json.RawMessage `json:"requester"`
	Target    json.RawMessage `json:"target"`
}

type searchBody struct {
	Indices       []string    `json:"indices"`
	Query         searchQuery `json:"query"`
	IncludeNested bool        `json:"includeNested"`
	Sort          []string    `json:"sort,omitempty"`
}

type searchQuery struct {
	Query string `json:"query"`
}

func (c *Client) listIdentities(ctx context.Context, _ *mcp.CallToolRequest, in ListIdentitiesInput) (*mcp.CallToolResult, idmcp.Page[IdentityItem], error) {
	q, offset, limit, err := collectionQuery(in.Limit, in.Offset)
	if err != nil {
		return nil, idmcp.Page[IdentityItem]{}, err
	}
	setQuery(q, "filters", in.Filters)
	setQuery(q, "sorters", in.Sorters)
	df := strings.TrimSpace(in.DefaultFilter)
	if df == "" {
		df = "CORRELATED_ONLY"
	}
	if df != "CORRELATED_ONLY" && df != "NONE" {
		return nil, idmcp.Page[IdentityItem]{}, fmt.Errorf("default_filter must be CORRELATED_ONLY or NONE")
	}
	q.Set("defaultFilter", df)
	var raw []rawIdentity
	if err := c.getJSON(ctx, "/identities", q, &raw); err != nil {
		return nil, idmcp.Page[IdentityItem]{}, err
	}
	items := make([]IdentityItem, 0, len(raw))
	for _, idn := range raw {
		items = append(items, identityItem(idn))
	}
	return nil, pageOf(items, offset, limit), nil
}

func (c *Client) getIdentity(ctx context.Context, _ *mcp.CallToolRequest, in GetIdentityInput) (*mcp.CallToolResult, IdentityItem, error) {
	if err := idmcp.Require("identity_id", in.IdentityID); err != nil {
		return nil, IdentityItem{}, err
	}
	var raw rawIdentity
	if err := c.getJSON(ctx, "/identities/"+url.PathEscape(in.IdentityID), nil, &raw); err != nil {
		return nil, IdentityItem{}, err
	}
	return nil, identityItem(raw), nil
}

func (c *Client) getIdentityAccess(ctx context.Context, _ *mcp.CallToolRequest, in GetIdentityAccessInput) (*mcp.CallToolResult, IdentityAccess, error) {
	var zero IdentityAccess
	if err := idmcp.Require("identity_id", in.IdentityID); err != nil {
		return nil, zero, err
	}
	var raw rawIdentity
	if err := c.getJSON(ctx, "/identities/"+url.PathEscape(in.IdentityID), nil, &raw); err != nil {
		return nil, zero, err
	}
	flt, err := identityIDFilter(in.IdentityID)
	if err != nil {
		return nil, zero, err
	}
	aq := url.Values{}
	aq.Set("filters", flt)
	aq.Set("detailLevel", "SLIM")
	aq.Set("limit", strconv.Itoa(nestedCap))
	var accounts []rawAccount
	if err := c.getJSON(ctx, "/accounts", aq, &accounts); err != nil {
		return nil, zero, err
	}
	eq := url.Values{}
	eq.Set("limit", strconv.Itoa(nestedCap))
	var ents []json.RawMessage
	if err := c.getJSON(ctx, "/entitlements/identities/"+url.PathEscape(in.IdentityID)+"/entitlements", eq, &ents); err != nil {
		return nil, zero, err
	}
	rq := url.Values{}
	rq.Set("limit", strconv.Itoa(nestedCap))
	var roles []json.RawMessage
	if err := c.getJSON(ctx, "/identities/"+url.PathEscape(in.IdentityID)+"/role-assignments", rq, &roles); err != nil {
		return nil, zero, err
	}

	accItems := make([]AccountItem, 0, len(accounts))
	for _, a := range accounts {
		if len(accItems) >= nestedCap {
			break
		}
		accItems = append(accItems, accountItem(a))
	}
	entItems := make([]EntitlementItem, 0, len(ents))
	for _, e := range ents {
		if len(entItems) >= nestedCap {
			break
		}
		entItems = append(entItems, entitlementItem(e))
	}
	roleItems := make([]RoleItem, 0, len(roles))
	for _, r := range roles {
		if len(roleItems) >= nestedCap {
			break
		}
		roleItems = append(roleItems, roleItem(r))
	}
	if accItems == nil {
		accItems = []AccountItem{}
	}
	if entItems == nil {
		entItems = []EntitlementItem{}
	}
	if roleItems == nil {
		roleItems = []RoleItem{}
	}
	idn := identityItem(raw)
	return nil, IdentityAccess{
		ID:                    idn.ID,
		Name:                  idn.Name,
		Alias:                 idn.Alias,
		Email:                 idn.Email,
		IdentityState:         idn.IdentityState,
		CloudLifecycle:        idn.CloudLifecycle,
		Accounts:              accItems,
		TruncatedAccounts:     len(accounts) >= nestedCap,
		Entitlements:          entItems,
		TruncatedEntitlements: len(ents) >= nestedCap,
		Roles:                 roleItems,
		TruncatedRoles:        len(roles) >= nestedCap,
	}, nil
}

func (c *Client) listAccounts(ctx context.Context, _ *mcp.CallToolRequest, in ListAccountsInput) (*mcp.CallToolResult, idmcp.Page[AccountItem], error) {
	q, offset, limit, err := collectionQuery(in.Limit, in.Offset)
	if err != nil {
		return nil, idmcp.Page[AccountItem]{}, err
	}
	setQuery(q, "filters", in.Filters)
	q.Set("detailLevel", "SLIM")
	var raw []rawAccount
	if err := c.getJSON(ctx, "/accounts", q, &raw); err != nil {
		return nil, idmcp.Page[AccountItem]{}, err
	}
	items := make([]AccountItem, 0, len(raw))
	for _, a := range raw {
		items = append(items, accountItem(a))
	}
	return nil, pageOf(items, offset, limit), nil
}

func (c *Client) listUncorrelatedAccounts(ctx context.Context, _ *mcp.CallToolRequest, in ListAccountsInput) (*mcp.CallToolResult, idmcp.Page[AccountItem], error) {
	in.Filters = withUncorrelated(in.Filters)
	return c.listAccounts(ctx, nil, in)
}

func (c *Client) listSources(ctx context.Context, _ *mcp.CallToolRequest, in ListSourcesInput) (*mcp.CallToolResult, idmcp.Page[SourceItem], error) {
	q, offset, limit, err := collectionQuery(in.Limit, in.Offset)
	if err != nil {
		return nil, idmcp.Page[SourceItem]{}, err
	}
	setQuery(q, "filters", in.Filters)
	var raw []rawSource
	if err := c.getJSON(ctx, "/sources", q, &raw); err != nil {
		return nil, idmcp.Page[SourceItem]{}, err
	}
	items := make([]SourceItem, 0, len(raw))
	for _, s := range raw {
		items = append(items, SourceItem{ID: s.ID, Name: s.Name, Type: s.Type, Healthy: s.Healthy, Status: s.Status})
	}
	return nil, pageOf(items, offset, limit), nil
}

func (c *Client) search(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, idmcp.Page[SearchHit], error) {
	if err := idmcp.Require("query", in.Query); err != nil {
		return nil, idmcp.Page[SearchHit]{}, err
	}
	indices := in.Indices
	if len(indices) == 0 {
		indices = []string{"identities"}
	}
	limit := in.Limit
	if limit <= 0 {
		limit = idmcp.DefaultLimit
	}
	if limit > searchCap {
		limit = searchCap
	}
	offset, err := idmcp.ParseIntCursor(in.Offset)
	if err != nil {
		return nil, idmcp.Page[SearchHit]{}, err
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	body := searchBody{
		Indices:       indices,
		Query:         searchQuery{Query: in.Query},
		IncludeNested: in.IncludeNested,
		Sort:          []string{"id"},
	}
	var raw []json.RawMessage
	if err := c.postJSON(ctx, "/search?"+q.Encode(), body, &raw); err != nil {
		return nil, idmcp.Page[SearchHit]{}, err
	}
	items := make([]SearchHit, 0, len(raw))
	for _, doc := range raw {
		items = append(items, searchHit(doc))
	}
	return nil, pageOf(items, offset, limit), nil
}

func (c *Client) findStaleIdentities(ctx context.Context, _ *mcp.CallToolRequest, in FindStaleIdentitiesInput) (*mcp.CallToolResult, StalePage, error) {
	want := idmcp.ClampLimit(in.Limit)
	offset, err := idmcp.ParseIntCursor(in.Offset)
	if err != nil {
		return nil, StalePage{}, err
	}
	items := make([]StaleItem, 0)
	scanned := 0
	lastN := 0
	lastOffset := offset
	pageLimit := idmcp.DefaultLimit
	for i := 0; i < idmcp.MaxStalePages && len(items) < want && scanned < staleScanCap; i++ {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(pageLimit))
		q.Set("offset", strconv.Itoa(offset))
		body := searchBody{
			Indices: []string{"identities"},
			Query:   searchQuery{Query: staleIdentityQuery},
			Sort:    []string{"id"},
		}
		var raw []json.RawMessage
		if err := c.postJSON(ctx, "/search?"+q.Encode(), body, &raw); err != nil {
			return nil, StalePage{}, err
		}
		lastOffset = offset
		inspect := raw
		clipped := false
		if room := staleScanCap - scanned; len(raw) > room {
			inspect = raw[:room]
			clipped = true
		}
		lastN = len(inspect)
		scanned += lastN
		leftover := false
		for _, doc := range inspect {
			hit := searchHit(doc)
			st := staleFromHit(doc, hit)
			if len(items) >= want {
				leftover = true
				continue
			}
			items = append(items, st)
		}
		if clipped {
			return nil, StalePage{Items: items, Next: strconv.Itoa(lastOffset), Truncated: true, Scanned: scanned}, nil
		}
		if leftover {
			return nil, StalePage{Items: items, Truncated: true, Scanned: scanned}, nil
		}
		nxt := idmcp.NextOffset(lastOffset, lastN, pageLimit)
		if nxt == "" || lastN == 0 {
			break
		}
		offset, _ = strconv.Atoi(nxt)
	}
	next := idmcp.NextOffset(lastOffset, lastN, pageLimit)
	if len(items) >= want {
		if items == nil {
			items = []StaleItem{}
		}
		return nil, StalePage{Items: items, Next: next, Truncated: next != "", Scanned: scanned}, nil
	}

	uq := url.Values{}
	uq.Set("filters", "uncorrelated eq true")
	uq.Set("detailLevel", "SLIM")
	uq.Set("limit", strconv.Itoa(uncorrelatedSample))
	var uncorr []rawAccount
	if err := c.getJSON(ctx, "/accounts", uq, &uncorr); err != nil {
		return nil, StalePage{}, err
	}
	scanned += len(uncorr)
	for _, a := range uncorr {
		if len(items) >= want {
			return nil, StalePage{Items: items, Truncated: true, Scanned: scanned}, nil
		}
		items = append(items, StaleItem{
			ID:           a.ID,
			Name:         a.Name,
			Reasons:      []string{"uncorrelated"},
			Uncorrelated: true,
		})
	}
	if items == nil {
		items = []StaleItem{}
	}
	return nil, StalePage{
		Items:     items,
		Next:      next,
		Truncated: next != "",
		Scanned:   scanned,
	}, nil
}

func (c *Client) listAccountActivities(ctx context.Context, _ *mcp.CallToolRequest, in ListAccountActivitiesInput) (*mcp.CallToolResult, idmcp.Page[AccountActivityItem], error) {
	offset, err := idmcp.ParseIntCursor(in.Offset)
	if err != nil {
		return nil, idmcp.Page[AccountActivityItem]{}, err
	}
	limit := idmcp.ClampLimit(in.Limit)
	if limit > activityCap {
		limit = activityCap
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	setQuery(q, "regarding-identity", in.RegardingIdentity)
	setQuery(q, "filters", in.Filters)
	var raw []rawActivity
	if err := c.getJSON(ctx, "/account-activities", q, &raw); err != nil {
		return nil, idmcp.Page[AccountActivityItem]{}, err
	}
	items := make([]AccountActivityItem, 0, len(raw))
	for _, a := range raw {
		items = append(items, AccountActivityItem{
			ID:        a.ID,
			Type:      a.Type,
			Requester: namedRef(a.Requester),
			Target:    namedRef(a.Target),
			Created:   a.Created,
		})
	}
	return nil, pageOf(items, offset, limit), nil
}

func (c *Client) listEntitlements(ctx context.Context, _ *mcp.CallToolRequest, in ListEntitlementsInput) (*mcp.CallToolResult, idmcp.Page[EntitlementItem], error) {
	q, offset, limit, err := collectionQuery(in.Limit, in.Offset)
	if err != nil {
		return nil, idmcp.Page[EntitlementItem]{}, err
	}
	setQuery(q, "filters", in.Filters)
	var raw []json.RawMessage
	if err := c.getJSON(ctx, "/entitlements", q, &raw); err != nil {
		return nil, idmcp.Page[EntitlementItem]{}, err
	}
	items := make([]EntitlementItem, 0, len(raw))
	for _, e := range raw {
		items = append(items, entitlementItem(e))
	}
	return nil, pageOf(items, offset, limit), nil
}

func identityItem(u rawIdentity) IdentityItem {
	life := ""
	if u.Attributes != nil {
		life = asString(u.Attributes["cloudLifecycleState"])
	}
	return IdentityItem{
		ID:             u.ID,
		Name:           u.Name,
		Alias:          u.Alias,
		Email:          u.Email,
		IdentityState:  u.IdentityState,
		CloudLifecycle: life,
	}
}

func accountItem(a rawAccount) AccountItem {
	return AccountItem{
		ID:             a.ID,
		SourceID:       a.SourceID,
		SourceName:     a.SourceName,
		NativeIdentity: a.NativeIdentity,
		Name:           a.Name,
		Disabled:       a.Disabled,
		Uncorrelated:   a.Uncorrelated,
	}
}

func entitlementItem(raw json.RawMessage) EntitlementItem {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return EntitlementItem{}
	}
	id := firstString(m, "id")
	name := firstString(m, "name")
	attr := firstString(m, "attribute")
	val := firstString(m, "value")
	sourceID := firstString(m, "sourceId")
	sourceName := firstString(m, "sourceName")
	if src := asMap(m["source"]); src != nil {
		if sourceID == "" {
			sourceID = firstString(src, "id")
		}
		if sourceName == "" {
			sourceName = firstString(src, "name")
		}
	}
	if nested := asMap(m["entitlement"]); nested != nil {
		if id == "" {
			id = firstString(nested, "id")
		}
		if name == "" {
			name = firstString(nested, "name")
		}
		if attr == "" {
			attr = firstString(nested, "attribute")
		}
		if val == "" {
			val = firstString(nested, "value")
		}
	}
	if ref := asMap(m["objectRef"]); ref != nil {
		if id == "" {
			id = firstString(ref, "id")
		}
		if name == "" {
			name = firstString(ref, "name")
		}
	}
	return EntitlementItem{ID: id, Name: name, Attribute: attr, Value: val, SourceID: sourceID, Source: sourceName}
}

func roleItem(raw json.RawMessage) RoleItem {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return RoleItem{}
	}
	id := firstString(m, "id")
	name := firstString(m, "name")
	typ := firstString(m, "type")
	if role := asMap(m["role"]); role != nil {
		if s := firstString(role, "id"); s != "" {
			id = s
		}
		if s := firstString(role, "name"); s != "" {
			name = s
		}
		if s := firstString(role, "type"); s != "" {
			typ = s
		}
	}
	return RoleItem{ID: id, Name: name, Type: typ}
}

func searchHit(raw json.RawMessage) SearchHit {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return SearchHit{}
	}
	return SearchHit{
		ID:    firstString(m, "id"),
		Name:  firstString(m, "name", "displayName"),
		Email: firstString(m, "email"),
		Type:  firstString(m, "_type", "type"),
	}
}

func staleFromHit(raw json.RawMessage, hit SearchHit) StaleItem {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	state := firstString(m, "identityState")
	reasons := []string{"inactive"}
	return StaleItem{
		ID:            hit.ID,
		Name:          hit.Name,
		Email:         hit.Email,
		Reasons:       reasons,
		IdentityState: state,
	}
}
