package c1

type ListUsersInput struct {
	Query      string `json:"query,omitempty" jsonschema:"search query"`
	Email      string `json:"email,omitempty" jsonschema:"email filter"`
	UserStatus string `json:"user_status,omitempty" jsonschema:"ENABLED, DISABLED, or DELETED"`
	RoleID     string `json:"role_id,omitempty" jsonschema:"role id; sent as roleIds"`
	Limit      int    `json:"limit,omitempty" jsonschema:"page size; under 10 is sent as 10, over 100 as 100, default 50"`
	PageToken  string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type UserItem struct {
	ID          string `json:"id" jsonschema:"ConductorOne user id"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	Status      string `json:"status,omitempty"`
	Type        string `json:"type,omitempty"`
	Department  string `json:"department,omitempty"`
	JobTitle    string `json:"job_title,omitempty"`
}

type GetUserInput struct {
	UserID string `json:"user_id" jsonschema:"ConductorOne user id"`
}

type UserDetail struct {
	ID          string   `json:"id" jsonschema:"ConductorOne user id"`
	DisplayName string   `json:"display_name,omitempty"`
	Email       string   `json:"email,omitempty"`
	Username    string   `json:"username,omitempty"`
	Status      string   `json:"status,omitempty"`
	Type        string   `json:"type,omitempty"`
	Department  string   `json:"department,omitempty"`
	JobTitle    string   `json:"job_title,omitempty"`
	RoleIDs     []string `json:"role_ids" jsonschema:"role ids from the user"`
	RoleNames   []string `json:"role_names,omitempty" jsonschema:"display names from expand role_ids; omitted when expand fails or is empty"`
}

type GetUserAccessInput struct {
	UserID string `json:"user_id" jsonschema:"ConductorOne user id"`
}

type AccountItem struct {
	AppID          string `json:"app_id,omitempty"`
	ID             string `json:"id" jsonschema:"app user id"`
	DisplayName    string `json:"display_name,omitempty"`
	Email          string `json:"email,omitempty"`
	Type           string `json:"type,omitempty" jsonschema:"app user type"`
	Status         string `json:"status,omitempty" jsonschema:"status.status"`
	IdentityUserID string `json:"identity_user_id,omitempty"`
	LastUsage      string `json:"last_usage,omitempty" jsonschema:"RFC3339 last usage when known"`
}

type GrantItem struct {
	AppID         string `json:"app_id,omitempty"`
	EntitlementID string `json:"entitlement_id,omitempty"`
	DisplayName   string `json:"display_name,omitempty"`
}

type UserAccess struct {
	ID                string        `json:"id"`
	DisplayName       string        `json:"display_name,omitempty"`
	Email             string        `json:"email,omitempty"`
	Username          string        `json:"username,omitempty"`
	Status            string        `json:"status,omitempty"`
	Type              string        `json:"type,omitempty"`
	Department        string        `json:"department,omitempty"`
	JobTitle          string        `json:"job_title,omitempty"`
	RoleIDs           []string      `json:"role_ids,omitempty"`
	Accounts          []AccountItem `json:"accounts" jsonschema:"app accounts, capped at 50"`
	TruncatedAccounts bool          `json:"truncated_accounts,omitempty"`
	Grants            []GrantItem   `json:"grants" jsonschema:"grants, capped at 50 from a single search"`
	TruncatedGrants   bool          `json:"truncated_grants,omitempty"`
}

type ListAppsInput struct {
	Query     string `json:"query,omitempty" jsonschema:"search query"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size; under 10 is sent as 10, over 100 as 100, default 50"`
	PageToken string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type AppItem struct {
	ID          string `json:"id" jsonschema:"app id"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	IsDirectory bool   `json:"is_directory" jsonschema:"true when the app is a directory"`
}

type ListAppUsersInput struct {
	AppID     string `json:"app_id" jsonschema:"app id"`
	Query     string `json:"query,omitempty" jsonschema:"search query"`
	Status    string `json:"status,omitempty" jsonschema:"STATUS_ENABLED, STATUS_DISABLED, or STATUS_DELETED"`
	Type      string `json:"type,omitempty" jsonschema:"APP_USER_TYPE_USER, APP_USER_TYPE_SERVICE_ACCOUNT, or APP_USER_TYPE_SYSTEM_ACCOUNT; aliases SERVICE_ACCOUNT and SYSTEM_ACCOUNT"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size; under 10 is sent as 10, over 100 as 100, default 50"`
	PageToken string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type ListEntitlementsInput struct {
	Query     string `json:"query,omitempty" jsonschema:"search query"`
	AppID     string `json:"app_id,omitempty" jsonschema:"optional app id; sent as appIds"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size; under 10 is sent as 10, over 100 as 100, default 50"`
	PageToken string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type EntitlementItem struct {
	ID          string `json:"id" jsonschema:"entitlement id"`
	AppID       string `json:"app_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Alias       string `json:"alias,omitempty"`
}

type ListUncorrelatedAccountsInput struct {
	AppID     string `json:"app_id,omitempty" jsonschema:"optional app id"`
	Query     string `json:"query,omitempty" jsonschema:"search query"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size; under 10 is sent as 10, over 100 as 100, default 50"`
	PageToken string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type FindStaleAccountsInput struct {
	AppID        string `json:"app_id,omitempty" jsonschema:"optional app id to restrict the scan"`
	Query        string `json:"query,omitempty" jsonschema:"optional search query"`
	InactiveDays int    `json:"inactive_days,omitempty" jsonschema:"treat last usage older than this many days as stale; default 90"`
	Limit        int    `json:"limit,omitempty" jsonschema:"max stale accounts to return; default 50, at most 500"`
	PageToken    string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type StaleAccount struct {
	AppID          string   `json:"app_id,omitempty"`
	ID             string   `json:"id" jsonschema:"app user id"`
	DisplayName    string   `json:"display_name,omitempty"`
	Email          string   `json:"email,omitempty"`
	Type           string   `json:"type,omitempty"`
	Status         string   `json:"status,omitempty"`
	IdentityUserID string   `json:"identity_user_id,omitempty"`
	LastUsage      string   `json:"last_usage,omitempty" jsonschema:"RFC3339 last usage when known; omitted when missing or not RFC3339"`
	Reasons        []string `json:"reasons" jsonschema:"STATUS_DISABLED, STATUS_DELETED, no_usage, and/or usage_older_than_N_days"`
}

type StalePage struct {
	Items     []StaleAccount `json:"items"`
	Next      string         `json:"next,omitempty"`
	Truncated bool           `json:"truncated,omitempty" jsonschema:"true if more matches exist. When true and next is empty, more matches are on the current page — re-call with a larger limit"`
	Scanned   int            `json:"scanned" jsonschema:"app-user rows inspected; a call inspects at most 500"`
}

type ListAccessReviewsInput struct {
	Limit     int    `json:"limit,omitempty" jsonschema:"page size; under 10 is sent as 10, over 100 as 100, default 50"`
	PageToken string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type AccessReviewItem struct {
	ID          string `json:"id" jsonschema:"access review id"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type ListTasksInput struct {
	Query          string `json:"query,omitempty" jsonschema:"search query"`
	UserID         string `json:"user_id,omitempty" jsonschema:"subject user id; sent as subjectIds"`
	AppID          string `json:"app_id,omitempty" jsonschema:"application id; sent as applicationIds"`
	AccessReviewID string `json:"access_review_id,omitempty" jsonschema:"access review id; sent as accessReviewIds"`
	State          string `json:"state,omitempty" jsonschema:"TASK_STATE_OPEN or TASK_STATE_CLOSED"`
	CreatedAfter   string `json:"created_after,omitempty" jsonschema:"createdAfter timestamp"`
	CreatedBefore  string `json:"created_before,omitempty" jsonschema:"createdBefore timestamp"`
	Limit          int    `json:"limit,omitempty" jsonschema:"page size; sent as at most 10"`
	PageToken      string `json:"page_token,omitempty" jsonschema:"opaque cursor from the previous page next field; not a URL"`
}

type TaskItem struct {
	ID          string `json:"id" jsonschema:"task id"`
	NumericID   string `json:"numeric_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`
	Type        string `json:"type,omitempty" jsonschema:"grant, revoke, certify, offboarding, action, or finding"`
	Outcome     string `json:"outcome,omitempty" jsonschema:"type.<kind>.outcome when present"`
	CreatedAt   string `json:"created_at,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	AppID       string `json:"app_id,omitempty" jsonschema:"app id for grant, revoke, or certify; otherwise empty"`
}
