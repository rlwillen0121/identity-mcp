package entra

import "strconv"

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type graphPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

type graphSignInActivity struct {
	LastSignInDateTime               string `json:"lastSignInDateTime"`
	LastNonInteractiveSignInDateTime string `json:"lastNonInteractiveSignInDateTime"`
	LastSuccessfulSignInDateTime     string `json:"lastSuccessfulSignInDateTime"`
}

type graphUser struct {
	ID                string               `json:"id"`
	DisplayName       string               `json:"displayName"`
	UserPrincipalName string               `json:"userPrincipalName"`
	Mail              string               `json:"mail"`
	AccountEnabled    *bool                `json:"accountEnabled"`
	CreatedDateTime   string               `json:"createdDateTime"`
	UserType          string               `json:"userType"`
	JobTitle          string               `json:"jobTitle"`
	Department        string               `json:"department"`
	SignInActivity    *graphSignInActivity `json:"signInActivity"`
}

type graphGroup struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"displayName"`
	Mail            string   `json:"mail"`
	SecurityEnabled *bool    `json:"securityEnabled"`
	GroupTypes      []string `json:"groupTypes"`
	MembershipRule  string   `json:"membershipRule"`
	ODataType       string   `json:"@odata.type"`
}

type graphDirectoryObject struct {
	ODataType         string   `json:"@odata.type"`
	ID                string   `json:"id"`
	DisplayName       string   `json:"displayName"`
	GroupTypes        []string `json:"groupTypes"`
	UserPrincipalName string   `json:"userPrincipalName"`
}

type graphDirectoryRole struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description"`
	RoleTemplateID string `json:"roleTemplateId"`
}

type graphServicePrincipal struct {
	ID                     string `json:"id"`
	AppID                  string `json:"appId"`
	DisplayName            string `json:"displayName"`
	AccountEnabled         *bool  `json:"accountEnabled"`
	ServicePrincipalType   string `json:"servicePrincipalType"`
	AppOwnerOrganizationID string `json:"appOwnerOrganizationId"`
}

type graphSignIn struct {
	ID                      string `json:"id"`
	CreatedDateTime         string `json:"createdDateTime"`
	UserPrincipalName       string `json:"userPrincipalName"`
	AppDisplayName          string `json:"appDisplayName"`
	IPAddress               string `json:"ipAddress"`
	ConditionalAccessStatus string `json:"conditionalAccessStatus"`
	Status                  struct {
		ErrorCode     int    `json:"errorCode"`
		FailureReason string `json:"failureReason"`
	} `json:"status"`
}

type ListUsersInput struct {
	Search    string `json:"search,omitempty" jsonschema:"displayName search sent as Graph $search or a startswith $filter"`
	Filter    string `json:"filter,omitempty" jsonschema:"raw Graph $filter; used when search is empty or to further narrow results"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max items to return (default 50, max 200)"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken or @odata.nextLink from a previous page"`
}

type User struct {
	ID          string `json:"id" jsonschema:"Entra object id"`
	DisplayName string `json:"display_name" jsonschema:"display name"`
	UPN         string `json:"upn" jsonschema:"userPrincipalName"`
	Mail        string `json:"mail,omitempty" jsonschema:"mail address"`
	Enabled     bool   `json:"enabled" jsonschema:"accountEnabled"`
	Created     string `json:"created,omitempty" jsonschema:"createdDateTime"`
	UserType    string `json:"user_type,omitempty" jsonschema:"Member or Guest"`
	JobTitle    string `json:"job_title,omitempty" jsonschema:"job title"`
	Department  string `json:"department,omitempty" jsonschema:"department"`
	LastSignIn  string `json:"last_sign_in,omitempty" jsonschema:"last successful or interactive sign-in"`
}

type GetUserInput struct {
	UserID string `json:"user_id" jsonschema:"user object id or userPrincipalName"`
}

type GroupRef struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	GroupTypes  []string `json:"group_types,omitempty"`
}

type UserDetail struct {
	ID              string     `json:"id"`
	DisplayName     string     `json:"display_name"`
	UPN             string     `json:"upn"`
	Mail            string     `json:"mail,omitempty"`
	Enabled         bool       `json:"enabled"`
	Created         string     `json:"created,omitempty"`
	UserType        string     `json:"user_type,omitempty"`
	JobTitle        string     `json:"job_title,omitempty"`
	Department      string     `json:"department,omitempty"`
	LastSignIn      string     `json:"last_sign_in,omitempty"`
	Groups          []GroupRef `json:"groups" jsonschema:"group memberships from memberOf"`
	GroupsTruncated bool       `json:"groups_truncated,omitempty" jsonschema:"true if more than 50 groups exist"`
}

type ListUserGroupsInput struct {
	UserID    string `json:"user_id" jsonschema:"user object id or userPrincipalName"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max groups to return (default 50, max 200)"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken from a previous page"`
}

type ListGroupsInput struct {
	Filter    string `json:"filter,omitempty" jsonschema:"raw Graph $filter"`
	Search    string `json:"search,omitempty" jsonschema:"displayName search via $search or startswith"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max items to return (default 50, max 200)"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken or @odata.nextLink from a previous page"`
}

type Group struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"display_name"`
	Mail            string   `json:"mail,omitempty"`
	SecurityEnabled bool     `json:"security_enabled"`
	GroupTypes      []string `json:"group_types"`
	MembershipRule  string   `json:"membership_rule,omitempty"`
}

type ListGroupMembersInput struct {
	GroupID   string `json:"group_id" jsonschema:"group object id"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max items to return (default 50, max 200)"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken or @odata.nextLink from a previous page"`
}

type DirectoryMember struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	UPN         string `json:"upn,omitempty"`
	Type        string `json:"type" jsonschema:"user, group, servicePrincipal, or other Graph directory object"`
}

type DirectoryRole struct {
	ID             string `json:"id"`
	DisplayName    string `json:"display_name"`
	Description    string `json:"description,omitempty"`
	RoleTemplateID string `json:"role_template_id,omitempty"`
}

type ListRoleMembersInput struct {
	RoleID    string `json:"role_id" jsonschema:"directory role object id"`
	Limit     int    `json:"limit,omitempty" jsonschema:"client-side cap after Graph returns the collection (default 50, max 1000). Graph does not support $top/$skiptoken on this path"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"must be omitted; Graph does not paginate /directoryRoles/{id}/members"`
}

type ListServicePrincipalsInput struct {
	Filter    string `json:"filter,omitempty" jsonschema:"raw Graph $filter"`
	Search    string `json:"search,omitempty" jsonschema:"displayName search via $search or startswith"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max items to return (default 50, max 200)"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken or @odata.nextLink from a previous page"`
}

type ServicePrincipal struct {
	ID            string `json:"id"`
	AppID         string `json:"app_id"`
	DisplayName   string `json:"display_name"`
	Enabled       bool   `json:"enabled"`
	Type          string `json:"type" jsonschema:"servicePrincipalType such as Application or ManagedIdentity"`
	AppOwnerOrgID string `json:"app_owner_org_id,omitempty"`
}

type FindStaleUsersInput struct {
	InactiveDays int    `json:"inactive_days,omitempty" jsonschema:"days without sign-in to treat as stale; default 90"`
	Limit        int    `json:"limit,omitempty" jsonschema:"max stale users to return (default 50, max 200)"`
	SkipToken    string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken from a previous page"`
}

type StaleUser struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	UPN         string   `json:"upn"`
	Enabled     bool     `json:"enabled"`
	LastSignIn  string   `json:"last_sign_in" jsonschema:"last sign-in timestamp, empty or unknown when unavailable"`
	Reasons     []string `json:"reasons" jsonschema:"disabled, no_sign_in, and/or sign_in_older_than_N_days"`
}

type FindStaleUsersOutput struct {
	Items     []StaleUser `json:"items" jsonschema:"users matching at least one stale reason"`
	Next      string      `json:"next,omitempty" jsonschema:"opaque cursor for the next page"`
	Truncated bool        `json:"truncated,omitempty" jsonschema:"true if more matches exist. When true and next is empty, more matches are on the current page — re-call with a larger limit. Inspects at most 500 accounts (10 pages of 50)"`
	Note      string      `json:"note,omitempty" jsonschema:"set when signInActivity is unavailable so last_sign_in is unknown"`
	Scanned   int         `json:"scanned" jsonschema:"directory rows inspected while collecting stale matches"`
}

type ListSignInsInput struct {
	Filter    string `json:"filter,omitempty" jsonschema:"raw Graph $filter such as createdDateTime ge 2024-01-01T00:00:00Z"`
	UserID    string `json:"user_id,omitempty" jsonschema:"user object id or UPN; added to $filter"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max sign-in rows to return (default 50, max 50)"`
	SkipToken string `json:"skip_token,omitempty" jsonschema:"opaque $skiptoken from a previous page"`
}

type SignIn struct {
	ID                string `json:"id"`
	Created           string `json:"created"`
	UserPrincipalName string `json:"user_principal_name"`
	AppDisplayName    string `json:"app_display_name"`
	IP                string `json:"ip"`
	StatusError       string `json:"status_error" jsonschema:"failure reason or error code; empty on success"`
	ConditionalAccess string `json:"conditional_access" jsonschema:"conditionalAccessStatus"`
}

func toUser(u graphUser) User {
	return User{
		ID:          u.ID,
		DisplayName: u.DisplayName,
		UPN:         u.UserPrincipalName,
		Mail:        u.Mail,
		Enabled:     enabledPtr(u.AccountEnabled),
		Created:     u.CreatedDateTime,
		UserType:    u.UserType,
		JobTitle:    u.JobTitle,
		Department:  u.Department,
		LastSignIn:  lastSignIn(u.SignInActivity),
	}
}

func toGroup(g graphGroup) Group {
	gt := g.GroupTypes
	if gt == nil {
		gt = []string{}
	}
	return Group{
		ID:              g.ID,
		DisplayName:     g.DisplayName,
		Mail:            g.Mail,
		SecurityEnabled: enabledPtr(g.SecurityEnabled),
		GroupTypes:      gt,
		MembershipRule:  g.MembershipRule,
	}
}

func toMember(o graphDirectoryObject) DirectoryMember {
	return DirectoryMember{
		ID:          o.ID,
		DisplayName: o.DisplayName,
		UPN:         o.UserPrincipalName,
		Type:        objectType(o.ODataType),
	}
}

func toRole(r graphDirectoryRole) DirectoryRole {
	return DirectoryRole{
		ID:             r.ID,
		DisplayName:    r.DisplayName,
		Description:    r.Description,
		RoleTemplateID: r.RoleTemplateID,
	}
}

func toSP(s graphServicePrincipal) ServicePrincipal {
	return ServicePrincipal{
		ID:            s.ID,
		AppID:         s.AppID,
		DisplayName:   s.DisplayName,
		Enabled:       enabledPtr(s.AccountEnabled),
		Type:          s.ServicePrincipalType,
		AppOwnerOrgID: s.AppOwnerOrganizationID,
	}
}

func toSignIn(s graphSignIn) SignIn {
	status := ""
	if s.Status.ErrorCode != 0 {
		status = s.Status.FailureReason
		if status == "" {
			status = strconv.Itoa(s.Status.ErrorCode)
		}
	}
	return SignIn{
		ID:                s.ID,
		Created:           s.CreatedDateTime,
		UserPrincipalName: s.UserPrincipalName,
		AppDisplayName:    s.AppDisplayName,
		IP:                s.IPAddress,
		StatusError:       status,
		ConditionalAccess: s.ConditionalAccessStatus,
	}
}
