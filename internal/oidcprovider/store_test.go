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
	ctx := WithBrowserBinding(context.Background(), "test-browser")
	_, err := s.CreateAuthRequest(context.Background(), &oidc.AuthRequest{}, "")
	require.Error(t, err, "a request without a browser binding must not be stored")
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
	signedInAt := time.Now().UTC()
	request := &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access", AuthTime: &signedInAt}
	_, first, _, err := s.CreateAccessAndRefreshTokens(ctx, request, "")
	require.NoError(t, err)
	r, err := s.TokenRequestByRefreshToken(ctx, first)
	require.NoError(t, err)
	_, second, _, err := s.CreateAccessAndRefreshTokens(ctx, r, first)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	_, err = s.TokenRequestByRefreshToken(ctx, second)
	require.NoError(t, err)

	authTime := time.Now().UTC().Add(-time.Hour)
	cookie, err := s.CreateSession(ctx, id, authTime)
	require.NoError(t, err)
	actual, restoredAuthTime, err := s.SessionUser(ctx, cookie)
	require.NoError(t, err)
	require.Equal(t, id, actual)
	require.WithinDuration(t, authTime, restoredAuthTime, time.Microsecond)
	require.Error(t, s.TerminateSession(ctx, id, "app"), "the provider hook cannot log out without browser validation")
	_, _, err = s.SessionUser(ctx, cookie)
	require.NoError(t, err)
	require.NoError(t, s.TerminateBrowserSession(ctx, cookie, id, "app"))
	_, _, err = s.SessionUser(ctx, cookie)
	require.Error(t, err)
	_, err = s.TokenRequestByRefreshToken(ctx, second)
	require.True(t, errors.Is(err, op.ErrInvalidRefreshToken))
}

func newRefreshChain(t *testing.T, s *Store, userID string) string {
	t.Helper()
	authTime := time.Now().UTC()
	_, value, _, err := s.CreateAccessAndRefreshTokens(context.Background(),
		&authRequest{ClientID: "app", UserID: userID, Scopes: "openid offline_access", AuthTime: &authTime}, "")
	require.NoError(t, err)
	return value
}

func rotateRefresh(t *testing.T, s *Store, value string) string {
	t.Helper()
	request, err := s.TokenRequestByRefreshToken(context.Background(), value)
	require.NoError(t, err)
	_, next, _, err := s.CreateAccessAndRefreshTokens(context.Background(), request, value)
	require.NoError(t, err)
	return next
}

type refreshResult struct {
	value string
	err   error
}

func TestRefreshReplayRevokesOnlyItsChain(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	userID, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)
	first := newRefreshChain(t, s, userID)
	second := rotateRefresh(t, s, first)
	third := rotateRefresh(t, s, second)
	independent := newRefreshChain(t, s, userID)
	// R1's own 30-day expiry can pass while R3 remains usable. Its used hash
	// must still identify the chain until the original 90-day deadline.
	require.NoError(t, s.db.Model(&refreshToken{}).Where("token_hash = ?", hash(first)).
		Update("expires_at", time.Now().UTC().Add(-time.Hour)).Error)

	used, err := s.TokenRequestByRefreshToken(ctx, first)
	require.NoError(t, err, "used hashes must remain available for replay detection")
	_, _, _, err = s.CreateAccessAndRefreshTokens(ctx, used, first)
	require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	_, err = s.TokenRequestByRefreshToken(ctx, third)
	require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	_, err = s.TokenRequestByRefreshToken(ctx, independent)
	require.NoError(t, err, "a different sign-in must keep its refresh token")

	var old refreshToken
	require.NoError(t, s.db.First(&old, "token_hash = ?", hash(first)).Error)
	require.NotNil(t, old.UsedAt)
	var family refreshFamily
	require.NoError(t, s.db.First(&family, "id = ?", old.FamilyID).Error)
	require.NotNil(t, family.RevokedAt)
}

func TestConcurrentRefreshReplayRevokesReplacement(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	userID, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)
	first := newRefreshChain(t, s, userID)
	request, err := s.TokenRequestByRefreshToken(ctx, first)
	require.NoError(t, err)

	results := make(chan refreshResult, 2)
	for range 2 {
		go func() {
			_, value, _, err := s.CreateAccessAndRefreshTokens(ctx, request, first)
			results <- refreshResult{value, err}
		}()
	}
	one, two := <-results, <-results
	success, replay := one, two
	if success.err != nil {
		success, replay = two, one
	}
	require.NoError(t, success.err)
	require.NotEmpty(t, success.value)
	require.ErrorIs(t, replay.err, op.ErrInvalidRefreshToken)
	_, err = s.TokenRequestByRefreshToken(ctx, success.value)
	require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

func TestConcurrentLogoutAndRefreshLeavesNoLiveToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	userID, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)
	first := newRefreshChain(t, s, userID)
	request, err := s.TokenRequestByRefreshToken(ctx, first)
	require.NoError(t, err)
	cookie, err := s.CreateSession(ctx, userID, time.Now().UTC())
	require.NoError(t, err)

	start := make(chan struct{})
	refreshed := make(chan refreshResult, 1)
	loggedOut := make(chan error, 1)
	go func() {
		<-start
		_, value, _, err := s.CreateAccessAndRefreshTokens(ctx, request, first)
		refreshed <- refreshResult{value, err}
	}()
	go func() {
		<-start
		loggedOut <- s.TerminateBrowserSession(ctx, cookie, userID, "app")
	}()
	close(start)
	result := <-refreshed
	require.NoError(t, <-loggedOut)
	if result.err == nil {
		_, err = s.TokenRequestByRefreshToken(ctx, result.value)
		require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	} else {
		require.ErrorIs(t, result.err, op.ErrInvalidRefreshToken)
	}
}

func TestRevokingUsedRefreshTokenEndsItsChain(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	userID, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)
	first := newRefreshChain(t, s, userID)
	second := rotateRefresh(t, s, first)
	independent := newRefreshChain(t, s, userID)

	owner, tokenID, err := s.GetRefreshTokenInfo(ctx, "app", first)
	require.NoError(t, err)
	require.Equal(t, userID, owner)
	require.Nil(t, s.RevokeToken(ctx, tokenID, owner, "app"))
	_, err = s.TokenRequestByRefreshToken(ctx, second)
	require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	_, err = s.TokenRequestByRefreshToken(ctx, independent)
	require.NoError(t, err)
}

func TestRefreshTokenCannotOutliveOriginalSignIn(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		elapsed time.Duration
	}{
		{"recent sign-in", 0},
		{"near 90-day limit", 89 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authTime := time.Now().UTC().Add(-tc.elapsed)
			request := &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access", AuthTime: &authTime}
			_, first, _, err := s.CreateAccessAndRefreshTokens(ctx, request, "")
			require.NoError(t, err)
			var firstRow refreshToken
			require.NoError(t, s.db.First(&firstRow, "token_hash = ?", hash(first)).Error)
			expectedExpiry := time.Now().UTC().Add(refreshTokenLifetime)
			if deadline := authTime.Add(refreshAbsoluteLifetime); deadline.Before(expectedExpiry) {
				expectedExpiry = deadline
			}
			require.WithinDuration(t, expectedExpiry, firstRow.ExpiresAt, time.Second)
			require.False(t, firstRow.ExpiresAt.After(authTime.Add(refreshAbsoluteLifetime)))

			loaded, err := s.TokenRequestByRefreshToken(ctx, first)
			require.NoError(t, err)
			_, second, _, err := s.CreateAccessAndRefreshTokens(ctx, loaded, first)
			require.NoError(t, err)
			var secondRow refreshToken
			require.NoError(t, s.db.First(&secondRow, "token_hash = ?", hash(second)).Error)
			require.Equal(t, firstRow.AuthTime, secondRow.AuthTime)
			require.WithinDuration(t, expectedExpiry, secondRow.ExpiresAt, time.Second)
			require.False(t, secondRow.ExpiresAt.After(authTime.Add(refreshAbsoluteLifetime)))
		})
	}
}

func TestRefreshTokenRejectsOldAuthentication(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, err := s.FindOrCreateGoogleUser(ctx, "google-1", "person@example.com")
	require.NoError(t, err)

	for _, authTime := range []time.Time{time.Time{}, time.Now().UTC().Add(-refreshAbsoluteLifetime), time.Now().UTC().Add(-300 * 24 * time.Hour)} {
		request := &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access", AuthTime: &authTime}
		_, _, _, err := s.CreateAccessAndRefreshTokens(ctx, request, "")
		require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
	}
	var count int64
	require.NoError(t, s.db.Model(&refreshToken{}).Count(&count).Error)
	require.Zero(t, count)

	// An existing token issued before this policy must not bypass it merely
	// because its individual 30-day expiry is still in the future.
	currentAuthTime := time.Now().UTC()
	request := &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access", AuthTime: &currentAuthTime}
	_, value, _, err := s.CreateAccessAndRefreshTokens(ctx, request, "")
	require.NoError(t, err)
	require.NoError(t, s.db.Model(&refreshToken{}).Where("token_hash = ?", hash(value)).Update("auth_time", time.Now().UTC().Add(-91*24*time.Hour)).Error)
	_, err = s.TokenRequestByRefreshToken(ctx, value)
	require.ErrorIs(t, err, op.ErrInvalidRefreshToken)
}

func TestExpiredCredentialsAreRejected(t *testing.T) {
	s := testStore(t)
	ctx := WithBrowserBinding(context.Background(), "test-browser")
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

	signedInAt := time.Now().UTC()
	_, refresh, _, err := s.CreateAccessAndRefreshTokens(ctx, &authRequest{ClientID: "app", UserID: id, Scopes: "openid offline_access", AuthTime: &signedInAt}, "")
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
