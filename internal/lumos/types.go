package lumos

type ListUsersInput struct {
	SearchTerm string `json:"search_term,omitempty" jsonschema:"search users by name or email"`
	ExactMatch bool   `json:"exact_match,omitempty" jsonschema:"if search_term is set, require an exact match"`
	Page       string `json:"page,omitempty" jsonschema:"pagination cursor from the previous page next field"`
	Limit      int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
}

type UserItem struct {
	ID         string `json:"id" jsonschema:"Lumos user id"`
	Email      string `json:"email,omitempty" jsonschema:"email"`
	GivenName  string `json:"given_name,omitempty" jsonschema:"given name"`
	FamilyName string `json:"family_name,omitempty" jsonschema:"family name"`
	Status     string `json:"status,omitempty" jsonschema:"user lifecycle status"`
}

type GetUserInput struct {
	UserID string `json:"user_id" jsonschema:"Lumos user id"`
}

type GetUserAccessInput struct {
	UserID string `json:"user_id" jsonschema:"Lumos user id"`
}

type AccountItem struct {
	ID               string `json:"id" jsonschema:"account id"`
	AppID            string `json:"app_id,omitempty" jsonschema:"app id"`
	AppName          string `json:"app_name,omitempty" jsonschema:"app display name"`
	Status           string `json:"status,omitempty" jsonschema:"account lifecycle status"`
	LastLogin        string `json:"last_login,omitempty" jsonschema:"last login or last activity timestamp when present"`
	UniqueIdentifier string `json:"unique_identifier,omitempty" jsonschema:"app-unique account identifier"`
}

type UserAccess struct {
	ID                string        `json:"id" jsonschema:"Lumos user id"`
	Email             string        `json:"email,omitempty"`
	GivenName         string        `json:"given_name,omitempty"`
	FamilyName        string        `json:"family_name,omitempty"`
	Status            string        `json:"status,omitempty"`
	Roles             []string      `json:"roles" jsonschema:"Lumos roles assigned to the user"`
	Accounts          []AccountItem `json:"accounts" jsonschema:"app accounts, capped at 50"`
	TruncatedAccounts bool          `json:"truncated_accounts,omitempty" jsonschema:"true if more than 50 accounts exist"`
}

type ListAppsInput struct {
	Page  string `json:"page,omitempty" jsonschema:"pagination cursor from the previous page next field"`
	Limit int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
}

type AppItem struct {
	ID       string `json:"id" jsonschema:"Lumos app id"`
	Name     string `json:"name" jsonschema:"display name"`
	Status   string `json:"status,omitempty" jsonschema:"app status such as APPROVED or DISCOVERED"`
	Category string `json:"category,omitempty" jsonschema:"AppStore category when present"`
}

type ListAppAccountsInput struct {
	AppID  string `json:"app_id" jsonschema:"Lumos app id"`
	Status string `json:"status,omitempty" jsonschema:"optional account lifecycle status filter"`
	Page   string `json:"page,omitempty" jsonschema:"pagination cursor from the previous page next field"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
}

type ListGroupsInput struct {
	Page  string `json:"page,omitempty" jsonschema:"pagination cursor from the previous page next field"`
	Limit int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
}

type GroupItem struct {
	ID   string `json:"id" jsonschema:"Lumos group id"`
	Name string `json:"name,omitempty" jsonschema:"group name"`
}

type ListGroupMembersInput struct {
	GroupID string `json:"group_id" jsonschema:"Lumos group id"`
	Page    string `json:"page,omitempty" jsonschema:"pagination cursor from the previous page next field"`
	Limit   int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
}

type FindStaleAccountsInput struct {
	AppID        string `json:"app_id,omitempty" jsonschema:"optional app id to restrict the scan"`
	InactiveDays int    `json:"inactive_days,omitempty" jsonschema:"treat last_login older than this many days as stale; default 90"`
	Limit        int    `json:"limit,omitempty" jsonschema:"max stale accounts to return; defaults to 50, max 200"`
	Page         string `json:"page,omitempty" jsonschema:"opaque pagination cursor from the previous page next field"`
}

type StaleAccount struct {
	ID               string   `json:"id" jsonschema:"account id"`
	AppID            string   `json:"app_id,omitempty"`
	AppName          string   `json:"app_name,omitempty"`
	Status           string   `json:"status,omitempty"`
	LastLogin        string   `json:"last_login,omitempty"`
	UniqueIdentifier string   `json:"unique_identifier,omitempty"`
	Reasons          []string `json:"reasons" jsonschema:"SUSPENDED/ARCHIVED/DEPROVISIONED/ACCESS_REMOVED/WAITING_MANUAL_REMOVAL, no_login, and/or login_older_than_N_days"`
}

type StalePage struct {
	Items     []StaleAccount `json:"items"`
	Next      string         `json:"next,omitempty"`
	Truncated bool           `json:"truncated,omitempty" jsonschema:"true if more matches exist. When true and next is empty, more matches are on the current page — re-call with a larger limit"`
	Scanned   int            `json:"scanned" jsonschema:"account rows inspected while collecting stale matches; a call inspects at most 500 accounts"`
}

type ListAccessReviewsInput struct {
	Page  string `json:"page,omitempty" jsonschema:"pagination cursor from the previous page next field"`
	Limit int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
}

type AccessReviewItem struct {
	ID          string   `json:"id" jsonschema:"access review id"`
	Name        string   `json:"name" jsonschema:"campaign name"`
	Status      string   `json:"status" jsonschema:"IN_PREPARATION, IN_PROGRESS, COMPLETED, SCHEDULED, …"`
	DeadlineAt  string   `json:"deadline_at,omitempty"`
	StartedAt   string   `json:"started_at,omitempty"`
	CompletedAt string   `json:"completed_at,omitempty"`
	AppNames    []string `json:"app_names,omitempty" jsonschema:"up to 20 app display names in this review"`
}

type ListActivityLogsInput struct {
	Since  string `json:"since,omitempty" jsonschema:"inclusive start time (ISO 8601)"`
	Until  string `json:"until,omitempty" jsonschema:"exclusive end time (ISO 8601)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
	Offset string `json:"offset,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type ActivityLogItem struct {
	EventHash             string `json:"event_hash" jsonschema:"event hash"`
	EventType             string `json:"event_type"`
	EventTypeUserFriendly string `json:"event_type_user_friendly,omitempty"`
	Outcome               string `json:"outcome,omitempty"`
	EventBeganAt          string `json:"event_began_at,omitempty"`
	ActorID               string `json:"actor_id,omitempty"`
	ActorEmail            string `json:"actor_email,omitempty"`
}
