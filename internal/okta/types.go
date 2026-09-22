package okta

type ListUsersInput struct {
	Search string `json:"search,omitempty" jsonschema:"Okta user search expression, for example profile.email eq \"ada@example.com\" or status eq \"ACTIVE\""`
	Filter string `json:"filter,omitempty" jsonschema:"Okta filter expression when search is not needed"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	After  string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type UserItem struct {
	ID          string `json:"id" jsonschema:"Okta user id"`
	Login       string `json:"login" jsonschema:"profile.login"`
	Email       string `json:"email" jsonschema:"profile.email"`
	Status      string `json:"status" jsonschema:"Okta user status"`
	Created     string `json:"created,omitempty" jsonschema:"created timestamp"`
	LastLogin   string `json:"last_login,omitempty" jsonschema:"lastLogin timestamp"`
	LastUpdated string `json:"last_updated,omitempty" jsonschema:"lastUpdated timestamp"`
}

type GetUserInput struct {
	IDOrLogin string `json:"id_or_login" jsonschema:"Okta user id or login"`
}

type UserDetail struct {
	ID          string            `json:"id" jsonschema:"Okta user id"`
	Login       string            `json:"login" jsonschema:"profile.login"`
	Email       string            `json:"email" jsonschema:"profile.email"`
	Status      string            `json:"status" jsonschema:"Okta user status"`
	Created     string            `json:"created,omitempty" jsonschema:"created timestamp"`
	LastLogin   string            `json:"last_login,omitempty" jsonschema:"lastLogin timestamp"`
	LastUpdated string            `json:"last_updated,omitempty" jsonschema:"lastUpdated timestamp"`
	Profile     map[string]string `json:"profile,omitempty" jsonschema:"selected profile fields: firstName, lastName, department, title, employeeNumber"`
}

type ListUserGroupsInput struct {
	UserID string `json:"user_id" jsonschema:"Okta user id"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	After  string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type ListGroupsInput struct {
	Q      string `json:"q,omitempty" jsonschema:"group name starts-with search"`
	Filter string `json:"filter,omitempty" jsonschema:"Okta group filter expression"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	After  string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type GroupItem struct {
	ID                    string `json:"id" jsonschema:"Okta group id"`
	Name                  string `json:"name" jsonschema:"group profile name"`
	Type                  string `json:"type" jsonschema:"OKTA_GROUP, APP_GROUP, or BUILT_IN"`
	Description           string `json:"description,omitempty" jsonschema:"group profile description"`
	LastMembershipUpdated string `json:"last_membership_updated,omitempty" jsonschema:"lastMembershipUpdated timestamp"`
}

type ListGroupUsersInput struct {
	GroupID string `json:"group_id" jsonschema:"Okta group id"`
	Limit   int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	After   string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type ListAppsInput struct {
	Q      string `json:"q,omitempty" jsonschema:"application name or label search"`
	Filter string `json:"filter,omitempty" jsonschema:"Okta app filter expression"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	After  string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type AppItem struct {
	ID         string `json:"id" jsonschema:"Okta application id"`
	Name       string `json:"name" jsonschema:"application name key"`
	Label      string `json:"label" jsonschema:"application display label"`
	Status     string `json:"status" jsonschema:"ACTIVE or INACTIVE"`
	SignOnMode string `json:"sign_on_mode,omitempty" jsonschema:"signOnMode such as SAML_2_0 or OPENID_CONNECT"`
}

type ListAppUsersInput struct {
	AppID string `json:"app_id" jsonschema:"Okta application id"`
	Limit int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 200"`
	After string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type AppUserItem struct {
	ID          string `json:"id" jsonschema:"assigned user id"`
	Status      string `json:"status" jsonschema:"assignment status"`
	LastUpdated string `json:"last_updated,omitempty" jsonschema:"lastUpdated timestamp"`
	Email       string `json:"email,omitempty" jsonschema:"profile.email if present"`
}

type ListAdminsInput struct {
	Limit int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 50"`
	After string `json:"after,omitempty" jsonschema:"pagination cursor from the previous page next field"`
}

type AdminItem struct {
	ID         string   `json:"id" jsonschema:"user id"`
	Email      string   `json:"email,omitempty" jsonschema:"email if present in the IAM payload"`
	Login      string   `json:"login,omitempty" jsonschema:"login if present in the IAM payload"`
	RoleLabels []string `json:"role_labels" jsonschema:"role labels when the IAM payload includes them"`
}

type FindStaleUsersInput struct {
	InactiveDays int    `json:"inactive_days,omitempty" jsonschema:"treat lastLogin older than this many days as stale; default 90"`
	Limit        int    `json:"limit,omitempty" jsonschema:"max stale users to return; defaults to 50, max 200"`
	After        string `json:"after,omitempty" jsonschema:"opaque pagination cursor from the previous page next field"`
}

type StalePage struct {
	Items     []StaleUser `json:"items"`
	Next      string      `json:"next,omitempty"`
	Truncated bool        `json:"truncated,omitempty" jsonschema:"true if more matches exist. When true and next is empty, more matches are on the current page — re-call with a larger limit"`
	Scanned   int         `json:"scanned" jsonschema:"directory rows inspected while collecting stale matches; a call inspects at most 500 accounts"`
}

type StaleUser struct {
	ID        string `json:"id" jsonschema:"Okta user id"`
	Login     string `json:"login" jsonschema:"profile.login"`
	Status    string `json:"status" jsonschema:"Okta user status"`
	LastLogin string `json:"last_login,omitempty" jsonschema:"lastLogin timestamp when present"`
	Reason    string `json:"reason" jsonschema:"no_login, login_older_than_N_days, unparsed_last_login, or non_active_status"`
}

type ListLogsInput struct {
	Since  string `json:"since,omitempty" jsonschema:"inclusive start time (ISO 8601)"`
	Until  string `json:"until,omitempty" jsonschema:"exclusive end time (ISO 8601)"`
	Filter string `json:"filter,omitempty" jsonschema:"Okta log filter expression, for example eventType eq \"user.session.start\""`
	Q      string `json:"q,omitempty" jsonschema:"keyword search across log events"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size; defaults to 50, max 100"`
	After  string `json:"after,omitempty" jsonschema:"opaque pagination cursor from the previous page next field"`
}

type LogItem struct {
	UUID           string `json:"uuid" jsonschema:"event uuid"`
	Published      string `json:"published" jsonschema:"published timestamp"`
	Actor          string `json:"actor" jsonschema:"actor summary"`
	EventType      string `json:"event_type" jsonschema:"Okta eventType"`
	DisplayMessage string `json:"display_message" jsonschema:"displayMessage"`
	Outcome        string `json:"outcome" jsonschema:"outcome result and reason"`
	Target         string `json:"target" jsonschema:"target summary"`
}
