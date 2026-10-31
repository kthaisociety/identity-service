package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/kthaisociety/identity-service/internal/database/databasetest"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	cfg := &config.Config{
		SigningKeyPEMBase64: base64.StdEncoding.EncodeToString(pemKey),
		CryptoKeyBase64:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Clients:             []config.Client{{ID: "app", Secret: "secret", RedirectURIs: []string{"http://127.0.0.1:8012/callback"}}},
	}
	store, _, err := NewStore(databasetest.Open(t), cfg)
	require.NoError(t, err)
	return store
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return der
}

func TestGoogleUsersUseStableSubjectAndNeverAutoLinkEmail(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, err := s.FindOrCreateGoogleUser(ctx, "google-1", "PERSON@EXAMPLE.COM")
	require.NoError(t, err)
	require.NotEmpty(t, id)
	again, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)
	require.Equal(t, id, again)
	var roles []userRole
	require.NoError(t, s.db.Find(&roles, "user_id = ?", id).Error)
	require.Equal(t, []userRole{{UserID: id, Role: "user"}}, roles)
	_, err = s.FindOrCreateGoogleUser(ctx, "other-google-sub", "person@example.com")
	require.ErrorIs(t, err, ErrAccountLinkRequired)
	// An imported account without a Google subject must keep its UUID until an
	// explicit linking policy is agreed; matching email alone is insufficient.
	require.NoError(t, s.db.Exec("INSERT INTO users (id, email) VALUES (?, ?)", "00000000-0000-0000-0000-000000000002", "imported@example.com").Error)
	_, err = s.FindOrCreateGoogleUser(ctx, "new-google-sub", "imported@example.com")
	require.ErrorIs(t, err, ErrAccountLinkRequired)
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "app", RedirectURI: "http://127.0.0.1:8012/callback",
		CodeChallenge: "challenge", CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"openid"},
	}, "")
	require.NoError(t, err)
	require.NoError(t, s.CompleteSessionLogin(ctx, a.GetID(), "00000000-0000-0000-0000-000000000001", time.Now().UTC()))
	require.NoError(t, s.SaveAuthCode(ctx, a.GetID(), "code"))
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, exchangeErr := s.AuthRequestByCode(ctx, "code")
			results <- exchangeErr
		}()
	}
	successes := 0
	for range 2 {
		if <-results == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes, "only one concurrent exchange may consume a code")
	_, err = s.AuthRequestByCode(ctx, "code")
	require.Error(t, err)
}

func TestRefreshTokenRotatesAndSessionEnds(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)
	request := &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access"}
	_, first, _, err := s.CreateAccessAndRefreshTokens(ctx, request, "")
	require.NoError(t, err)
	r, err := s.TokenRequestByRefreshToken(ctx, first)
	require.NoError(t, err)
	_, second, _, err := s.CreateAccessAndRefreshTokens(ctx, r, first)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	_, err = s.TokenRequestByRefreshToken(ctx, first)
	require.True(t, errors.Is(err, op.ErrInvalidRefreshToken))
	_, err = s.TokenRequestByRefreshToken(ctx, second)
	require.NoError(t, err)

	authTime := time.Now().UTC().Add(-time.Hour)
	cookie, err := s.CreateSession(ctx, id, authTime)
	require.NoError(t, err)
	actual, restoredAuthTime, err := s.SessionUser(ctx, cookie)
	require.NoError(t, err)
	require.Equal(t, id, actual)
	require.WithinDuration(t, authTime, restoredAuthTime, time.Microsecond)
	require.NoError(t, s.EndSession(ctx, cookie))
	_, _, err = s.SessionUser(ctx, cookie)
	require.Error(t, err)
}

func TestExpiredCredentialsAreRejected(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)

	a, err := s.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "app", RedirectURI: "http://127.0.0.1:8012/callback",
		CodeChallenge: "challenge", CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"openid"},
	}, "")
	require.NoError(t, err)
	require.NoError(t, s.CompleteSessionLogin(ctx, a.GetID(), id, time.Now().UTC()))
	require.NoError(t, s.SaveAuthCode(ctx, a.GetID(), "expired-code"))
	require.NoError(t, s.db.Exec("UPDATE oidc_auth_requests SET code_expires_at = ? WHERE id = ?", time.Now().Add(-time.Minute), a.GetID()).Error)
	_, err = s.AuthRequestByCode(ctx, "expired-code")
	require.Error(t, err)

	_, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access"}, "")
	require.NoError(t, err)
	require.NoError(t, s.db.Exec("UPDATE oidc_refresh_tokens SET expires_at = ? WHERE token_hash = ?", time.Now().Add(-time.Minute), hash(refresh)).Error)
	_, err = s.TokenRequestByRefreshToken(ctx, refresh)
	require.ErrorIs(t, err, op.ErrInvalidRefreshToken)

	cookie, err := s.CreateSession(ctx, id, time.Now().UTC())
	require.NoError(t, err)
	require.NoError(t, s.db.Exec("UPDATE oidc_sessions SET expires_at = ? WHERE id_hash = ?", time.Now().Add(-time.Minute), hash(cookie)).Error)
	_, _, err = s.SessionUser(ctx, cookie)
	require.Error(t, err)
}
