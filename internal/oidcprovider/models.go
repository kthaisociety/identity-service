package oidcprovider

import (
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// user and userRole are our KTHAIS database models, not library interfaces.
type user struct {
	ID        string `gorm:"primaryKey;type:uuid"`
	Email     string
	GoogleSub string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type userRole struct {
	UserID string `gorm:"primaryKey;type:uuid"`
	Role   string `gorm:"primaryKey"`
}

func (userRole) TableName() string { return "user_roles" }

// authRequest is the durable state behind the library's authorization flow.
// Its getters and Done method implement op.AuthRequest; TableName is for GORM.
type authRequest struct {
	ID                  string `gorm:"primaryKey"`
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              string
	ResponseType        string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	AuthTime            *time.Time
	IsDone              bool `gorm:"column:done"`
	CreatedAt           time.Time
	CodeHash            *string
	CodeExpiresAt       *time.Time
	CodeUsed            bool
	GoogleStateHash     *string
}

func (authRequest) TableName() string        { return "oidc_auth_requests" }
func (a *authRequest) GetID() string         { return a.ID }
func (a *authRequest) GetACR() string        { return "" }
func (a *authRequest) GetAMR() []string      { return []string{"google"} }
func (a *authRequest) GetAudience() []string { return []string{a.ClientID} }
func (a *authRequest) GetAuthTime() time.Time {
	if a.AuthTime == nil {
		return time.Time{}
	}
	return *a.AuthTime
}
func (a *authRequest) GetClientID() string { return a.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.CodeChallenge, Method: oidc.CodeChallengeMethod(a.CodeChallengeMethod)}
}
func (a *authRequest) GetNonce() string                   { return a.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(a.ResponseType) }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(a.ResponseMode) }
func (a *authRequest) GetScopes() []string                { return strings.Fields(a.Scopes) }
func (a *authRequest) GetState() string                   { return a.State }
func (a *authRequest) GetSubject() string                 { return a.UserID }
func (a *authRequest) Done() bool                         { return a.IsDone }

var _ op.AuthRequest = (*authRequest)(nil)

// refreshToken is a database row whose methods implement op.RefreshTokenRequest.
type refreshToken struct {
	TokenHash string `gorm:"primaryKey"`
	UserID    string `gorm:"type:uuid"`
	ClientID  string
	Scopes    string
	AuthTime  time.Time
	ExpiresAt time.Time
}

func (refreshToken) TableName() string                   { return "oidc_refresh_tokens" }
func (r *refreshToken) GetAMR() []string                 { return []string{"google"} }
func (r *refreshToken) GetAudience() []string            { return []string{r.ClientID} }
func (r *refreshToken) GetAuthTime() time.Time           { return r.AuthTime }
func (r *refreshToken) GetClientID() string              { return r.ClientID }
func (r *refreshToken) GetScopes() []string              { return strings.Fields(r.Scopes) }
func (r *refreshToken) GetSubject() string               { return r.UserID }
func (r *refreshToken) SetCurrentScopes(scopes []string) { r.Scopes = strings.Join(scopes, " ") }

var _ op.RefreshTokenRequest = (*refreshToken)(nil)

// session is our identity browser session, not a library interface type.
type session struct {
	IDHash    string `gorm:"primaryKey"`
	UserID    string `gorm:"type:uuid"`
	AuthTime  time.Time
	ExpiresAt time.Time
}

func (session) TableName() string { return "oidc_sessions" }
