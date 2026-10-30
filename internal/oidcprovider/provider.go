package oidcprovider

import (
	"strings"

	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// New wires the library's protocol handlers to KTHAIS's durable storage.
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
