package oidcprovider

import (
	"net/url"
	"time"

	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type client struct {
	config.Client
	dev bool
}

func (c client) GetID() string                       { return c.ID }
func (c client) RedirectURIs() []string              { return c.Client.RedirectURIs }
func (c client) PostLogoutRedirectURIs() []string    { return c.Client.PostLogoutRedirectURIs }
func (c client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c client) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c client) LoginURL(id string) string                                { return "/login?authRequestID=" + url.QueryEscape(id) }
func (c client) AccessTokenType() op.AccessTokenType                      { return op.AccessTokenTypeJWT }
func (c client) IDTokenLifetime() time.Duration                           { return time.Hour }
func (c client) DevMode() bool                                            { return c.dev }
func (c client) RestrictAdditionalIdTokenScopes() func([]string) []string { return passthroughScopes }
func (c client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return passthroughScopes
}
func (c client) IsScopeAllowed(scope string) bool     { return false }
func (c client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c client) ClockSkew() time.Duration             { return 0 }

func passthroughScopes(scopes []string) []string { return scopes }

var _ op.Client = client{}
