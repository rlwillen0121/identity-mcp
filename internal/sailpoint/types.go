package sailpoint

type ListIdentitiesInput struct {
	Filters       string `json:"filters,omitempty" jsonschema:"ISC filter expression, for example email eq \"ada@example.com\""`
	Sorters       string `json:"sorters,omitempty" jsonschema:"ISC sorter expression, for example name"`
	DefaultFilter string `json:"default_filter,omitempty" jsonschema:"CORRELATED_ONLY (default) or NONE"`
	Limit         int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	Offset        string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type IdentityItem struct {
	ID             string `json:"id" jsonschema:"identity id"`
	Name           string `json:"name,omitempty"`
	Alias          string `json:"alias,omitempty"`
	Email          string `json:"email,omitempty"`
	IdentityState  string `json:"identity_state,omitempty" jsonschema:"identityState"`
	CloudLifecycle string `json:"cloud_lifecycle,omitempty" jsonschema:"attributes.cloudLifecycleState when present"`
}

type GetIdentityInput struct {
	IdentityID string `json:"identity_id" jsonschema:"identity id"`
}

type GetIdentityAccessInput struct {
	IdentityID string `json:"identity_id" jsonschema:"identity id"`
}

type AccountItem struct {
	ID             string `json:"id" jsonschema:"account id"`
	SourceID       string `json:"source_id,omitempty"`
	SourceName     string `json:"source_name,omitempty"`
	NativeIdentity string `json:"native_identity,omitempty"`
	Name           string `json:"name,omitempty"`
	Disabled       bool   `json:"disabled"`
	Uncorrelated   bool   `json:"uncorrelated"`
}

type EntitlementItem struct {
	ID        string `json:"id" jsonschema:"entitlement id"`
	Name      string `json:"name,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Value     string `json:"value,omitempty"`
	SourceID  string `json:"source_id,omitempty"`
	Source    string `json:"source,omitempty" jsonschema:"source name when nested"`
}

type RoleItem struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type IdentityAccess struct {
	ID                    string            `json:"id"`
	Name                  string            `json:"name,omitempty"`
	Alias                 string            `json:"alias,omitempty"`
	Email                 string            `json:"email,omitempty"`
	IdentityState         string            `json:"identity_state,omitempty"`
	CloudLifecycle        string            `json:"cloud_lifecycle,omitempty"`
	Accounts              []AccountItem     `json:"accounts"`
	TruncatedAccounts     bool              `json:"truncated_accounts,omitempty"`
	Entitlements          []EntitlementItem `json:"entitlements"`
	TruncatedEntitlements bool              `json:"truncated_entitlements,omitempty"`
	Roles                 []RoleItem        `json:"roles"`
	TruncatedRoles        bool              `json:"truncated_roles,omitempty"`
}

type ListAccountsInput struct {
	Filters string `json:"filters,omitempty" jsonschema:"raw ISC filters string (identityId, sourceId, …)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	Offset  string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type ListSourcesInput struct {
	Filters string `json:"filters,omitempty" jsonschema:"raw ISC filters string"`
	Limit   int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	Offset  string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type SourceItem struct {
	ID      string `json:"id" jsonschema:"source id"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
	Healthy *bool  `json:"healthy,omitempty"`
	Status  string `json:"status,omitempty"`
}

type SearchInput struct {
	Query         string   `json:"query" jsonschema:"ISC search query string"`
	Indices       []string `json:"indices,omitempty" jsonschema:"search indices; default [\"identities\"]"`
	IncludeNested bool     `json:"include_nested,omitempty" jsonschema:"include nested documents; default false"`
	Limit         int      `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 50"`
	Offset        string   `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type SearchHit struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Type  string `json:"type,omitempty"`
}

type FindStaleIdentitiesInput struct {
	InactiveDays int    `json:"inactive_days,omitempty" jsonschema:"accepted for parity with other find_stale tools; matching is by inactive lifecycle/state, not last login"`
	Limit        int    `json:"limit,omitempty" jsonschema:"max stale identities to return; defaults to 50, max 200"`
	Offset       string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type StaleItem struct {
	ID            string   `json:"id"`
	Name          string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	Reasons       []string `json:"reasons"`
	IdentityState string   `json:"identity_state,omitempty"`
	Uncorrelated  bool     `json:"uncorrelated"`
}

type StalePage struct {
	Items     []StaleItem `json:"items"`
	Next      string      `json:"next,omitempty"`
	Truncated bool        `json:"truncated,omitempty" jsonschema:"true if more matches exist. When true and next is empty, more matches are on the current page — re-call with a larger limit"`
	Scanned   int         `json:"scanned" jsonschema:"identity rows inspected while collecting stale matches; a call inspects at most 500 identities plus a bounded uncorrelated sample"`
}

type ListAccountActivitiesInput struct {
	RegardingIdentity string `json:"regarding_identity,omitempty" jsonschema:"identity id for regarding-identity"`
	Filters           string `json:"filters,omitempty" jsonschema:"raw ISC filters string"`
	Limit             int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
	Offset            string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type AccountActivityItem struct {
	ID        string `json:"id"`
	Type      string `json:"type,omitempty"`
	Requester string `json:"requester,omitempty"`
	Target    string `json:"target,omitempty"`
	Created   string `json:"created,omitempty"`
}

type ListEntitlementsInput struct {
	Filters string `json:"filters,omitempty" jsonschema:"raw ISC filters string"`
	Limit   int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	Offset  string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}
