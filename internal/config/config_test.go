package config

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateNamesEveryMissingVariable(t *testing.T) {
	err := (&Config{PublicPort: "8000", InternalPort: "8001"}).Validate()

	assert.EqualError(t, err, "missing required environment variables: DATABASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, IDENTITY_SERVICE_SECRET, OIDC_CLIENTS_JSON, OIDC_CRYPTO_KEY_BASE64, OIDC_ISSUER, OIDC_SIGNING_KEY_PEM_BASE64")
}

func validConfig() *Config {
	return &Config{
		DatabaseURL: "postgres://x", ServiceSecret: "s", PublicPort: "8000", InternalPort: "8001",
		Issuer: "http://127.0.0.1:8010", GoogleClientID: "google", GoogleClientSecret: "secret",
		GoogleRedirectURI:   "http://127.0.0.1:8010/auth/callback",
		SigningKeyPEMBase64: base64.StdEncoding.EncodeToString([]byte("key")),
		CryptoKeyBase64:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		ClientsJSON:         `[{"id":"app","secret":"secret","redirect_uris":["http://127.0.0.1:8012/callback"]}]`,
	}
}

func TestValidateRejectsTheSamePortTwice(t *testing.T) {
	c := validConfig()
	c.InternalPort = c.PublicPort

	assert.Error(t, c.Validate())
}

func TestValidateRequiresExactGoogleCallbackOrigin(t *testing.T) {
	c := validConfig()
	c.GoogleRedirectURI = "http://evil.example/auth/callback"
	assert.ErrorContains(t, c.Validate(), "GOOGLE_REDIRECT_URI")
}

func TestValidateRejectsWildcardClientRedirect(t *testing.T) {
	c := validConfig()
	c.ClientsJSON = `[{"id":"app","secret":"secret","redirect_uris":["https://*.example.com/callback"]}]`
	assert.ErrorContains(t, c.Validate(), "redirect URI")
}
