package oidcprovider

import (
	"strings"

	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// New wires ZITADEL's OIDC endpoints to our Store. Its HTTP handler is passed
// to Gin, while our /login and /auth/callback handlers perform Google sign-in.
func New(store *Store, key [32]byte, cfg *config.Config) (*op.Provider, error) {
	options := []op.Option{}
	if strings.HasPrefix(cfg.Issuer, "http://") {
		options = append(options, op.WithAllowInsecure())
	}
	return op.NewProvider(&op.Config{
		CryptoKey:                key,
		CryptoKeyId:              "identity-v1",
		DefaultLogoutRedirectURI: cfg.Issuer + "/signed-out",
		CodeMethodS256:           true,
		GrantTypeRefreshToken:    true,
	}, store, op.StaticIssuer(cfg.Issuer), options...)
}
