package googleauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestExchangeOnlyAcceptsVerifiedGoogleIdentity(t *testing.T) {
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var issuer, idToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &trustedKey.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": idToken})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	client, err := newClient(context.Background(), issuer, "google-client", "secret", issuer+"/auth/callback", server.Client())
	require.NoError(t, err)

	valid := func() map[string]any {
		return map[string]any{
			"iss": issuer, "aud": "google-client", "sub": "google-sub", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "email": "person@example.com", "email_verified": true,
		}
	}
	sign := func(key *rsa.PrivateKey, claims map[string]any) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: &jose.JSONWebKey{Key: key, KeyID: "test"}}, nil)
		require.NoError(t, err)
		value, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		return value
	}
	tests := []struct {
		name   string
		change func(map[string]any)
		key    *rsa.PrivateKey
		valid  bool
	}{
		{"valid", func(map[string]any) {}, trustedKey, true},
		{"wrong signature", func(map[string]any) {}, otherKey, false},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example" }, trustedKey, false},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other-client" }, trustedKey, false},
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, trustedKey, false},
		{"unverified email", func(c map[string]any) { c["email_verified"] = false }, trustedKey, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := valid()
			tt.change(claims)
			idToken = sign(tt.key, claims)
			identity, err := client.Exchange(context.Background(), "google-code")
			if tt.valid {
				require.NoError(t, err)
				require.Equal(t, Identity{Subject: "google-sub", Email: "person@example.com"}, identity)
			} else {
				require.Error(t, err)
				require.Empty(t, identity)
			}
		})
	}
}
