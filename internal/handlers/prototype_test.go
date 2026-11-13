package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/kthaisociety/identity-service/internal/database/databasetest"
	"github.com/kthaisociety/identity-service/internal/googleauth"
	"github.com/kthaisociety/identity-service/internal/oidcprovider"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/op"
	"gorm.io/gorm"
)

type fakeGoogle struct {
	calls   int
	subject string
	email   string
}

func (g *fakeGoogle) AuthURL(state string) string {
	return "https://google.example/authorize?state=" + url.QueryEscape(state)
}
func (g *fakeGoogle) Exchange(_ context.Context, code string) (googleauth.Identity, error) {
	g.calls++
	if code != "valid" {
		return googleauth.Identity{}, context.Canceled
	}
	subject, email := g.subject, g.email
	if subject == "" {
		subject, email = "google-sub", "person@example.com"
	}
	return googleauth.Identity{Subject: subject, Email: email}, nil
}

type prototype struct {
	router        http.Handler
	db            *gorm.DB
	google        *fakeGoogle
	browserCookie *http.Cookie
}

func newPrototype(t *testing.T) *prototype {
	t.Helper()
	ginTestMode()
	db := databasetest.Open(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	cfg := &config.Config{
		Issuer:              "http://127.0.0.1:8010",
		SigningKeyPEMBase64: base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		CryptoKeyBase64:     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		Clients: []config.Client{
			{ID: "app", Secret: "secret", RedirectURIs: []string{"http://127.0.0.1:8012/callback"}, PostLogoutRedirectURIs: []string{"http://127.0.0.1:8012/"}},
			{ID: "other", Secret: "other-secret", RedirectURIs: []string{"http://127.0.0.1:8013/callback"}},
		},
	}
	store, encryptionKey, err := oidcprovider.NewStore(db, cfg)
	require.NoError(t, err)
	provider, err := oidcprovider.New(store, encryptionKey, cfg)
	require.NoError(t, err)
	google := new(fakeGoogle)
	router := NewPublicRouter(Deps{
		PingDB: func(context.Context) error { return nil }, Provider: provider, AuthStore: store,
		Google: google, AuthCallbackURL: op.AuthCallbackURL(provider), Issuer: cfg.Issuer,
	})
	return &prototype{router: router, db: db, google: google}
}

func ginTestMode() { gin.SetMode(gin.TestMode) }

func (p *prototype) request(method, path string, form url.Values, cookie *http.Cookie, id, secret string) *httptest.ResponseRecorder {
	return p.requestWithBrowser(method, path, form, cookie, p.browserCookie, id, secret)
}

func (p *prototype) requestWithBrowser(method, path string, form url.Values, cookie, browser *http.Cookie, id, secret string) *httptest.ResponseRecorder {
	return p.requestWithBrowserAndSite(method, path, form, cookie, browser, id, secret, "same-site")
}

func (p *prototype) requestWithBrowserAndSite(method, path string, form url.Values, cookie, browser *http.Cookie, id, secret, site string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if site != "" {
		req.Header.Set("Sec-Fetch-Site", site)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if browser != nil && (cookie == nil || cookie.Name != browser.Name) {
		req.AddCookie(browser)
	}
	if id != "" {
		req.SetBasicAuth(id, secret)
	}
	w := httptest.NewRecorder()
	p.router.ServeHTTP(w, req)
	return w
}

func pathFromLocation(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	return u.RequestURI()
}

func authorizationQuery() (url.Values, string) {
	verifier := "a-very-long-pkce-verifier-created-by-the-client"
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {"http://127.0.0.1:8012/callback"},
		"scope": {"openid email offline_access"}, "state": {"app-state"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	return query, verifier
}

func (p *prototype) authorize(t *testing.T) (string, string) {
	t.Helper()
	query, verifier := authorizationQuery()
	w := p.request(http.MethodGet, "/authorize?"+query.Encode(), nil, nil, "", "")
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	var binding *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authBrowserCookie {
			binding = cookie
		}
	}
	require.NotNil(t, binding)
	require.True(t, binding.HttpOnly)
	require.Equal(t, "/", binding.Path)
	p.browserCookie = binding
	return pathFromLocation(t, w), verifier
}

func (p *prototype) beginGoogle(t *testing.T) (string, *http.Cookie, string) {
	t.Helper()
	loginPath, verifier := p.authorize(t)
	login := p.request(http.MethodGet, loginPath, nil, nil, "", "")
	require.Equal(t, http.StatusFound, login.Code)
	googleURL, err := url.Parse(login.Header().Get("Location"))
	require.NoError(t, err)
	state := googleURL.Query().Get("state")
	require.NotEmpty(t, state)
	require.Empty(t, login.Result().Cookies(), "the browser binding is reused across sign-ins")
	return state, p.browserCookie, verifier
}

func (p *prototype) signIn(t *testing.T) (string, *http.Cookie, string) {
	t.Helper()
	state, browserCookie, verifier := p.beginGoogle(t)
	callbackPath := "/auth/callback?state=" + url.QueryEscape(state) + "&code=valid"
	require.Equal(t, http.StatusBadRequest, p.requestWithBrowser(http.MethodGet, callbackPath, nil, nil, nil, "", "").Code)
	wrongBrowser := *browserCookie
	wrongBrowser.Value = "wrong"
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodGet, callbackPath, nil, &wrongBrowser, "", "").Code)
	callback := p.request(http.MethodGet, callbackPath, nil, browserCookie, "", "")
	require.Equal(t, http.StatusFound, callback.Code, callback.Body.String())
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodGet, callbackPath, nil, browserCookie, "", "").Code)
	cookies := callback.Result().Cookies()
	var session *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == sessionCookie {
			session = cookie
		}
	}
	require.NotNil(t, session)
	issued := p.request(http.MethodGet, pathFromLocation(t, callback), nil, session, "", "")
	require.Equal(t, http.StatusFound, issued.Code, issued.Body.String())
	appURL, err := url.Parse(issued.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8012/callback", appURL.Scheme+"://"+appURL.Host+appURL.Path)
	require.Equal(t, "app-state", appURL.Query().Get("state"))
	return appURL.Query().Get("code"), session, verifier
}

func (p *prototype) exchange(code, verifier, clientID, clientSecret, redirect string) *httptest.ResponseRecorder {
	return p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier},
	}, nil, clientID, clientSecret)
}

func (p *prototype) refresh(value, clientID, secret string) *httptest.ResponseRecorder {
	return p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {value},
	}, nil, clientID, secret)
}

func TestOIDCFlowAndRefresh(t *testing.T) {
	p := newPrototype(t)
	discovery := p.request(http.MethodGet, "/.well-known/openid-configuration", nil, nil, "", "")
	require.Equal(t, http.StatusOK, discovery.Code)
	var metadata struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	require.NoError(t, json.Unmarshal(discovery.Body.Bytes(), &metadata))
	require.Equal(t, "http://127.0.0.1:8010", metadata.Issuer)
	require.Equal(t, metadata.Issuer+"/authorize", metadata.AuthorizationEndpoint)
	require.Equal(t, metadata.Issuer+"/oauth/token", metadata.TokenEndpoint)
	require.Equal(t, metadata.Issuer+"/keys", metadata.JWKSURI)
	keys := p.request(http.MethodGet, "/keys", nil, nil, "", "")
	require.Equal(t, http.StatusOK, keys.Code)
	var jwks jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(keys.Body.Bytes(), &jwks))
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, jose.RS256, jose.SignatureAlgorithm(jwks.Keys[0].Algorithm))
	code, cookie, verifier := p.signIn(t)
	require.Equal(t, 1, p.google.calls)
	response := p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	require.NotEmpty(t, tokens.IDToken)
	authTime := func(raw string) int64 {
		parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		var claims struct {
			AuthTime int64 `json:"auth_time"`
		}
		require.NoError(t, parsed.Claims(jwks.Keys[0].Key, &claims))
		return claims.AuthTime
	}
	firstAuthTime := authTime(tokens.IDToken)
	require.Positive(t, firstAuthTime)
	assertJWT := func(raw string, expectedRoles []string) {
		parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		var claims struct {
			Issuer    string   `json:"iss"`
			Subject   string   `json:"sub"`
			Audience  []string `json:"aud"`
			Roles     []string `json:"roles"`
			ExpiresAt int64    `json:"exp"`
		}
		require.NoError(t, parsed.Claims(jwks.Keys[0].Key, &claims))
		require.Equal(t, "http://127.0.0.1:8010", claims.Issuer)
		require.NotEmpty(t, claims.Subject)
		require.Equal(t, []string{"app"}, claims.Audience)
		require.ElementsMatch(t, expectedRoles, claims.Roles)
		require.WithinDuration(t, time.Now().Add(time.Hour), time.Unix(claims.ExpiresAt, 0), time.Minute)
	}
	assertJWT(tokens.AccessToken, []string{"user"})
	require.Equal(t, http.StatusBadRequest, p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback").Code)

	// An app cannot silently reuse another app's code or a different redirect URI.
	for _, tc := range []struct{ id, secret, redirect string }{
		{"other", "other-secret", "http://127.0.0.1:8012/callback"},
		{"app", "secret", "http://127.0.0.1:8013/callback"},
	} {
		freshCode, _, freshVerifier := p.signIn(t)
		require.Equal(t, http.StatusBadRequest, p.exchange(freshCode, freshVerifier, tc.id, tc.secret, tc.redirect).Code)
	}

	// A second app visit can reuse the identity cookie without Google.
	loginPath, secondVerifier := p.authorize(t)
	login := p.request(http.MethodGet, loginPath, nil, cookie, "", "")
	require.Equal(t, http.StatusFound, login.Code)
	require.Contains(t, login.Header().Get("Location"), "/authorize/callback")
	require.Equal(t, 3, p.google.calls)
	secondCodeRedirect := p.request(http.MethodGet, pathFromLocation(t, login), nil, cookie, "", "")
	require.Equal(t, http.StatusFound, secondCodeRedirect.Code)
	secondLocation, err := url.Parse(secondCodeRedirect.Header().Get("Location"))
	require.NoError(t, err)
	secondTokens := p.exchange(secondLocation.Query().Get("code"), secondVerifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, secondTokens.Code, secondTokens.Body.String())
	var secondResponse struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(secondTokens.Body.Bytes(), &secondResponse))
	require.Equal(t, firstAuthTime, authTime(secondResponse.IDToken))

	var userID string
	require.NoError(t, p.db.Raw("SELECT id FROM users WHERE google_sub = ?", "google-sub").Scan(&userID).Error)
	require.NoError(t, p.db.Exec("INSERT INTO user_roles (user_id, role) VALUES (?, ?)", userID, "member").Error)
	wrongClient := p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "other", "other-secret")
	require.NotEqual(t, http.StatusOK, wrongClient.Code)
	wrongSecret := p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "app", "wrong-secret")
	require.NotEqual(t, http.StatusOK, wrongSecret.Code)
	refresh := p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "app", "secret")
	require.Equal(t, http.StatusOK, refresh.Code, refresh.Body.String())
	var renewed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(refresh.Body.Bytes(), &renewed))
	assertJWT(renewed.AccessToken, []string{"user", "member"})
	require.NotEqual(t, tokens.RefreshToken, renewed.RefreshToken)
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "app", "secret").Code)
	revoke := p.request(http.MethodPost, "/revoke", url.Values{
		"token": {renewed.RefreshToken}, "token_type_hint": {"refresh_token"},
	}, nil, "app", "secret")
	require.Equal(t, http.StatusOK, revoke.Code, revoke.Body.String())
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {renewed.RefreshToken},
	}, nil, "app", "secret").Code)

	logoutQuery := url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {"http://127.0.0.1:8012/"}}
	logout := p.request(http.MethodGet, "/end_session?"+logoutQuery.Encode(), nil, cookie, "", "")
	require.Equal(t, http.StatusFound, logout.Code, logout.Body.String())
	require.Equal(t, "http://127.0.0.1:8012/", logout.Header().Get("Location"))
	loginPath, _ = p.authorize(t)
	login = p.request(http.MethodGet, loginPath, nil, cookie, "", "")
	require.Equal(t, http.StatusFound, login.Code)
	require.Contains(t, login.Header().Get("Location"), "google.example/authorize")
}

func TestRefreshRejectsOldOriginalSignIn(t *testing.T) {
	p := newPrototype(t)
	code, _, verifier := p.signIn(t)
	issued := p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, issued.Code)
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &tokens))
	require.NoError(t, p.db.Exec("UPDATE oidc_refresh_tokens SET auth_time = now() - interval '91 days', expires_at = now() + interval '1 day'").Error)
	renewed := p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "app", "secret")
	require.Equal(t, http.StatusBadRequest, renewed.Code, renewed.Body.String())
	require.Contains(t, renewed.Body.String(), "invalid_grant")
	var count int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens").Scan(&count).Error)
	require.EqualValues(t, 1, count, "a rejected refresh must not issue another token")
}

func TestRefreshReplayRevokesOnlyThePresentedChain(t *testing.T) {
	p := newPrototype(t)
	_, tokens := p.issueLogoutTokens(t)
	decodeRefresh := func(response *httptest.ResponseRecorder) string {
		t.Helper()
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		var body struct {
			RefreshToken string `json:"refresh_token"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
		require.NotEmpty(t, body.RefreshToken)
		return body.RefreshToken
	}
	second := decodeRefresh(p.refresh(tokens.RefreshToken, "app", "secret"))
	require.Equal(t, http.StatusBadRequest, p.refresh(tokens.RefreshToken, "other", "other-secret").Code)
	third := decodeRefresh(p.refresh(second, "app", "secret"))

	replayed := p.refresh(tokens.RefreshToken, "app", "secret")
	require.Equal(t, http.StatusBadRequest, replayed.Code, replayed.Body.String())
	require.Contains(t, replayed.Body.String(), "invalid_grant")
	require.Equal(t, http.StatusBadRequest, p.refresh(third, "app", "secret").Code)
}

func TestRevokingUsedRefreshThroughEndpointEndsItsChain(t *testing.T) {
	p := newPrototype(t)
	_, tokens := p.issueLogoutTokens(t)
	renewed := p.refresh(tokens.RefreshToken, "app", "secret")
	require.Equal(t, http.StatusOK, renewed.Code, renewed.Body.String())
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(renewed.Body.Bytes(), &body))
	require.NotEmpty(t, body.RefreshToken)
	// An expired predecessor must still identify and revoke its refresh family.
	require.NoError(t, p.db.Exec("UPDATE oidc_refresh_tokens SET expires_at = now() - interval '1 day' WHERE used_at IS NOT NULL").Error)

	revoked := p.request(http.MethodPost, "/revoke", url.Values{
		"token": {tokens.RefreshToken}, "token_type_hint": {"refresh_token"},
	}, nil, "app", "secret")
	require.Equal(t, http.StatusOK, revoked.Code, revoked.Body.String())
	require.Equal(t, http.StatusBadRequest, p.refresh(body.RefreshToken, "app", "secret").Code)
}

func TestRefreshReadFailuresAreRetryable(t *testing.T) {
	for _, table := range []string{"oidc_refresh_tokens", "oidc_refresh_families", "users", "user_roles"} {
		t.Run(table, func(t *testing.T) {
			p := newPrototype(t)
			_, tokens := p.issueLogoutTokens(t)
			hidden := table + "_unavailable"
			require.NoError(t, p.db.Exec("ALTER TABLE "+table+" RENAME TO "+hidden).Error)
			restored := false
			t.Cleanup(func() {
				if !restored {
					require.NoError(t, p.db.Exec("ALTER TABLE "+hidden+" RENAME TO "+table).Error)
				}
			})

			failed := p.refresh(tokens.RefreshToken, "app", "secret")
			assertSafeTokenServerError(t, failed, http.StatusServiceUnavailable, tokens.RefreshToken)
			require.NoError(t, p.db.Exec("ALTER TABLE "+hidden+" RENAME TO "+table).Error)
			restored = true
			require.Equal(t, http.StatusOK, p.refresh(tokens.RefreshToken, "app", "secret").Code,
				"the same token must work after storage recovers")
		})
	}
}

func TestFailedRefreshRotationDoesNotConsumeToken(t *testing.T) {
	p := newPrototype(t)
	_, tokens := p.issueLogoutTokens(t)
	const constraint = "reject_refresh_use"
	require.NoError(t, p.db.Exec("ALTER TABLE oidc_refresh_tokens ADD CONSTRAINT "+constraint+" CHECK (used_at IS NULL)").Error)
	removed := false
	t.Cleanup(func() {
		if !removed {
			require.NoError(t, p.db.Exec("ALTER TABLE oidc_refresh_tokens DROP CONSTRAINT "+constraint).Error)
		}
	})

	failed := p.refresh(tokens.RefreshToken, "app", "secret")
	assertSafeTokenServerError(t, failed, http.StatusInternalServerError, tokens.RefreshToken)
	var count, used int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens").Scan(&count).Error)
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens WHERE used_at IS NOT NULL").Scan(&used).Error)
	require.EqualValues(t, 1, count, "a failed rotation must not issue a replacement")
	require.Zero(t, used, "a failed rotation must not consume the original token")

	require.NoError(t, p.db.Exec("ALTER TABLE oidc_refresh_tokens DROP CONSTRAINT "+constraint).Error)
	removed = true
	require.Equal(t, http.StatusOK, p.refresh(tokens.RefreshToken, "app", "secret").Code,
		"the original token must work after storage recovers")
}

func TestInvalidRefreshTokensRemainInvalidGrants(t *testing.T) {
	p := newPrototype(t)
	missing := p.refresh("not-issued", "app", "secret")
	require.Equal(t, http.StatusBadRequest, missing.Code)
	require.Contains(t, missing.Body.String(), "invalid_grant")

	_, tokens := p.issueLogoutTokens(t)
	require.NoError(t, p.db.Exec("UPDATE oidc_refresh_tokens SET expires_at = now() - interval '1 second'").Error)
	expired := p.refresh(tokens.RefreshToken, "app", "secret")
	require.Equal(t, http.StatusBadRequest, expired.Code)
	require.Contains(t, expired.Body.String(), "invalid_grant")
}

func assertSafeTokenServerError(t *testing.T, response *httptest.ResponseRecorder, status int, token string) {
	t.Helper()
	require.Equal(t, status, response.Code, response.Body.String())
	require.JSONEq(t, `{"error":"server_error"}`, response.Body.String())
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	for _, sensitive := range []string{token, "secret", "oidc_refresh_tokens", "oidc_refresh_families", "invalid_grant"} {
		require.NotContains(t, response.Body.String(), sensitive)
	}
}

func TestAuthorizeRejectsUnsupportedParsedOptions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra string
	}{
		{"prompt", "prompt=login"},
		{"mixed-case prompt", "PROMPT=login"},
		{"max age", "max_age=0"},
		{"mixed-case max age", "MAX_AGE=0"},
		{"empty later challenge", "code_challenge="},
		{"later plain method", "code_challenge_method=plain"},
		{"fragment response", "response_mode=fragment"},
		{"form response", "response_mode=form_post"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPrototype(t)
			query, _ := authorizationQuery()
			response := p.request(http.MethodGet, "/authorize?"+query.Encode()+"&"+tc.extra, nil, nil, "", "")
			require.Equal(t, http.StatusFound, response.Code, response.Body.String())
			location, err := url.Parse(response.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "http://127.0.0.1:8012/callback", location.Scheme+"://"+location.Host+location.Path)
			errorCode := location.Query().Get("error")
			if errorCode == "" {
				fragment, err := url.ParseQuery(location.Fragment)
				require.NoError(t, err)
				errorCode = fragment.Get("error")
			}
			require.Equal(t, "invalid_request", errorCode)
			var count int64
			require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_auth_requests").Scan(&count).Error)
			require.Zero(t, count)
		})
	}

	p := newPrototype(t)
	query, _ := authorizationQuery()
	query.Set("response_mode", "query")
	response := p.request(http.MethodGet, "/authorize?"+query.Encode(), nil, nil, "", "")
	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, "/login", strings.Split(pathFromLocation(t, response), "?")[0])
}

func TestAuthorizationRequestRequiresStartingBrowser(t *testing.T) {
	p := newPrototype(t)
	_, session, _ := p.signIn(t)
	victimBrowser := p.browserCookie

	// A second browser starts an app sign-in; the signed-in browser cannot
	// complete that pending request with its SSO session.
	p.browserCookie = nil
	loginPath, _ := p.authorize(t)
	otherBrowser := p.browserCookie
	login := p.requestWithBrowser(http.MethodGet, loginPath, nil, session, victimBrowser, "", "")
	require.Equal(t, http.StatusBadRequest, login.Code)
	requestID, err := url.Parse(loginPath)
	require.NoError(t, err)
	var done bool
	require.NoError(t, p.db.Raw("SELECT done FROM oidc_auth_requests WHERE id = ?", requestID.Query().Get("authRequestID")).Scan(&done).Error)
	require.False(t, done)

	// The originating browser can still continue its own request.
	login = p.requestWithBrowser(http.MethodGet, loginPath, nil, nil, otherBrowser, "", "")
	require.Equal(t, http.StatusFound, login.Code)
	require.Contains(t, login.Header().Get("Location"), "google.example/authorize")
}

func TestAuthorizationCallbacksRequireStartingBrowser(t *testing.T) {
	p := newPrototype(t)
	state, browserCookie, _ := p.beginGoogle(t)
	browser := p.browserCookie
	callbackPath := "/auth/callback?state=" + url.QueryEscape(state) + "&code=valid"

	missing := p.requestWithBrowser(http.MethodGet, callbackPath, nil, nil, nil, "", "")
	require.Equal(t, http.StatusBadRequest, missing.Code)
	wrong := *browser
	wrong.Value = "wrong-browser"
	mismatch := p.requestWithBrowser(http.MethodGet, callbackPath, nil, nil, &wrong, "", "")
	require.Equal(t, http.StatusBadRequest, mismatch.Code)
	require.Zero(t, p.google.calls, "Google code must not be exchanged for another browser")

	callback := p.request(http.MethodGet, callbackPath, nil, browserCookie, "", "")
	require.Equal(t, http.StatusFound, callback.Code)
	finishPath := pathFromLocation(t, callback)
	require.Equal(t, http.StatusBadRequest, p.requestWithBrowser(http.MethodGet, finishPath, nil, nil, nil, "", "").Code)
	require.Equal(t, http.StatusBadRequest, p.requestWithBrowser(http.MethodGet, finishPath, nil, nil, &wrong, "", "").Code)
	issued := p.request(http.MethodGet, finishPath, nil, nil, "", "")
	require.Equal(t, http.StatusFound, issued.Code)
	require.NotEmpty(t, issued.Header().Get("Location"))
}

func TestTwoTabsKeepTheSameBrowserBinding(t *testing.T) {
	p := newPrototype(t)
	_, session, _ := p.signIn(t)
	first, _ := p.authorize(t)
	value := p.browserCookie.Value
	second, _ := p.authorize(t)
	require.Equal(t, value, p.browserCookie.Value)
	for _, path := range []string{first, second} {
		login := p.request(http.MethodGet, path, nil, session, "", "")
		require.Equal(t, http.StatusFound, login.Code)
		issued := p.request(http.MethodGet, pathFromLocation(t, login), nil, nil, "", "")
		require.Equal(t, http.StatusFound, issued.Code)
	}
}

func TestTwoTabsCanFinishGoogleSignIn(t *testing.T) {
	p := newPrototype(t)
	firstState, _, _ := p.beginGoogle(t)
	value := p.browserCookie.Value
	secondState, _, _ := p.beginGoogle(t)
	require.Equal(t, value, p.browserCookie.Value)
	for _, state := range []string{firstState, secondState} {
		callback := p.request(http.MethodGet, "/auth/callback?state="+url.QueryEscape(state)+"&code=valid", nil, nil, "", "")
		require.Equal(t, http.StatusFound, callback.Code)
		issued := p.request(http.MethodGet, pathFromLocation(t, callback), nil, nil, "", "")
		require.Equal(t, http.StatusFound, issued.Code)
	}
}

func TestAuthorizationRejectsWrongPKCEVerifier(t *testing.T) {
	p := newPrototype(t)
	code, _, verifier := p.signIn(t)
	require.NotEqual(t, http.StatusOK, p.exchange(code, verifier+"wrong", "app", "secret", "http://127.0.0.1:8012/callback").Code)
	// A failed exchange cannot turn the same code into a token later.
	require.NotEqual(t, http.StatusOK, p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback").Code)
}

type logoutTokens struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func (p *prototype) issueLogoutTokens(t *testing.T) (*http.Cookie, logoutTokens) {
	t.Helper()
	code, cookie, verifier := p.signIn(t)
	issued := p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, issued.Code, issued.Body.String())
	var tokens logoutTokens
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &tokens))
	return cookie, tokens
}

func TestLogoutWithIDTokenHintEndsSessionAndRefresh(t *testing.T) {
	p := newPrototype(t)
	cookie, tokens := p.issueLogoutTokens(t)
	// The same person can have another identity session, and an independent app
	// can hold a refresh token. Logout must target the user's sessions and only
	// the requesting app's refresh tokens.
	secondCookie, secondTokens := p.issueLogoutTokens(t)
	var userID string
	require.NoError(t, p.db.Raw("SELECT id FROM users WHERE google_sub = ?", "google-sub").Scan(&userID).Error)
	otherFamily := "00000000-0000-0000-0000-000000000042"
	require.NoError(t, p.db.Exec(`INSERT INTO oidc_refresh_families (id, user_id, client_id, expires_at)
		VALUES (?, ?, 'other', now() + interval '90 days')`, otherFamily, userID).Error)
	require.NoError(t, p.db.Exec(`INSERT INTO oidc_refresh_tokens
		(token_hash, family_id, user_id, client_id, scopes, auth_time, expires_at)
		VALUES (?, ?, ?, ?, ?, now(), now() + interval '1 day')`,
		"another-app-token", otherFamily, userID, "other", "openid").Error)
	query := url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {"http://127.0.0.1:8012/"}, "state": {"logout-state"}}
	logout := p.request(http.MethodGet, "/end_session?"+query.Encode(), nil, cookie, "", "")
	require.Equal(t, http.StatusFound, logout.Code, logout.Body.String())
	redirect, err := url.Parse(logout.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8012/", redirect.Scheme+"://"+redirect.Host+redirect.Path)
	require.Equal(t, "logout-state", redirect.Query().Get("state"))
	var sessions, appRefreshes, otherRefreshes int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_sessions WHERE user_id = ?", userID).Scan(&sessions).Error)
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_families WHERE user_id = ? AND client_id = 'app' AND revoked_at IS NULL", userID).Scan(&appRefreshes).Error)
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_families WHERE user_id = ? AND client_id = 'other' AND revoked_at IS NULL", userID).Scan(&otherRefreshes).Error)
	require.Zero(t, sessions)
	require.Zero(t, appRefreshes)
	require.EqualValues(t, 1, otherRefreshes)
	loginPath, _ := p.authorize(t)
	login := p.request(http.MethodGet, loginPath, nil, cookie, "", "")
	require.Contains(t, login.Header().Get("Location"), "google.example/authorize")
	login = p.request(http.MethodGet, loginPath, nil, secondCookie, "", "")
	require.Contains(t, login.Header().Get("Location"), "google.example/authorize")
	require.NotEqual(t, http.StatusOK, p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "app", "secret").Code)
	require.NotEqual(t, http.StatusOK, p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {secondTokens.RefreshToken},
	}, nil, "app", "secret").Code)
}

func TestRejectedLogoutPreservesSessionAndRefresh(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		call   func(*prototype, *http.Cookie, string) *httptest.ResponseRecorder
	}{
		{"no hint", http.StatusBadRequest, func(p *prototype, cookie *http.Cookie, _ string) *httptest.ResponseRecorder {
			return p.request(http.MethodGet, "/end_session?client_id=app", nil, cookie, "", "")
		}},
		{"missing cookie", http.StatusBadRequest, func(p *prototype, _ *http.Cookie, hint string) *httptest.ResponseRecorder {
			return p.request(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(hint), nil, nil, "", "")
		}},
		{"wrong cookie", http.StatusBadRequest, func(p *prototype, cookie *http.Cookie, hint string) *httptest.ResponseRecorder {
			wrong := *cookie
			wrong.Value = "wrong-session"
			return p.request(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(hint), nil, &wrong, "", "")
		}},
		{"invalid hint", http.StatusBadRequest, func(p *prototype, cookie *http.Cookie, _ string) *httptest.ResponseRecorder {
			return p.request(http.MethodGet, "/end_session?id_token_hint=invalid", nil, cookie, "", "")
		}},
		{"different client", http.StatusBadRequest, func(p *prototype, cookie *http.Cookie, hint string) *httptest.ResponseRecorder {
			return p.request(http.MethodGet, "/end_session?client_id=other&id_token_hint="+url.QueryEscape(hint), nil, cookie, "", "")
		}},
		{"invalid redirect", http.StatusBadRequest, func(p *prototype, cookie *http.Cookie, hint string) *httptest.ResponseRecorder {
			query := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://unregistered.example/"}}
			return p.request(http.MethodGet, "/end_session?"+query.Encode(), nil, cookie, "", "")
		}},
		{"cross site", http.StatusForbidden, func(p *prototype, cookie *http.Cookie, hint string) *httptest.ResponseRecorder {
			return p.requestWithBrowserAndSite(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(hint), nil, cookie, nil, "", "", "cross-site")
		}},
		{"cross site POST", http.StatusForbidden, func(p *prototype, cookie *http.Cookie, hint string) *httptest.ResponseRecorder {
			return p.requestWithBrowserAndSite(http.MethodPost, "/end_session", url.Values{"id_token_hint": {hint}}, cookie, nil, "", "", "cross-site")
		}},
		{"unknown source", http.StatusForbidden, func(p *prototype, cookie *http.Cookie, hint string) *httptest.ResponseRecorder {
			return p.requestWithBrowserAndSite(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(hint), nil, cookie, nil, "", "", "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPrototype(t)
			cookie, tokens := p.issueLogoutTokens(t)
			response := tc.call(p, cookie, tokens.IDToken)
			require.Equal(t, tc.status, response.Code, response.Body.String())
			require.Empty(t, response.Header().Values("Set-Cookie"))
			var sessions, refreshes int64
			require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_sessions").Scan(&sessions).Error)
			require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens").Scan(&refreshes).Error)
			require.EqualValues(t, 1, sessions)
			require.EqualValues(t, 1, refreshes)
			renewed := p.request(http.MethodPost, "/oauth/token", url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
			}, nil, "app", "secret")
			require.Equal(t, http.StatusOK, renewed.Code, renewed.Body.String())
			valid := p.request(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(tokens.IDToken), nil, cookie, "", "")
			require.Equal(t, http.StatusFound, valid.Code, valid.Body.String())
		})
	}
}

func TestExpiredBrowserSessionCannotLogout(t *testing.T) {
	p := newPrototype(t)
	cookie, tokens := p.issueLogoutTokens(t)
	require.NoError(t, p.db.Exec("UPDATE oidc_sessions SET expires_at = now() - interval '1 second'").Error)
	response := p.request(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(tokens.IDToken), nil, cookie, "", "")
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Empty(t, response.Header().Values("Set-Cookie"))
	var refreshes int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens").Scan(&refreshes).Error)
	require.EqualValues(t, 1, refreshes)
}

func TestLogoutHintMustMatchBrowserUser(t *testing.T) {
	p := newPrototype(t)
	firstCookie, _ := p.issueLogoutTokens(t)
	p.google.subject, p.google.email = "another-google-sub", "another@example.com"
	secondCookie, tokens := p.issueLogoutTokens(t)
	response := p.request(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(tokens.IDToken), nil, firstCookie, "", "")
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Empty(t, response.Header().Values("Set-Cookie"))
	var sessions, refreshes int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_sessions").Scan(&sessions).Error)
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens").Scan(&refreshes).Error)
	require.EqualValues(t, 2, sessions)
	require.EqualValues(t, 2, refreshes)
	require.NotEqual(t, firstCookie.Value, secondCookie.Value)
}

func TestLogoutAcceptsPOST(t *testing.T) {
	p := newPrototype(t)
	cookie, tokens := p.issueLogoutTokens(t)
	response := p.request(http.MethodPost, "/end_session", url.Values{
		"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {"http://127.0.0.1:8012/"},
	}, cookie, "", "")
	require.Equal(t, http.StatusFound, response.Code, response.Body.String())
	require.Equal(t, "http://127.0.0.1:8012/", response.Header().Get("Location"))
	require.NotEmpty(t, response.Header().Values("Set-Cookie"))
	var sessions int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_sessions").Scan(&sessions).Error)
	require.Zero(t, sessions)
}

func TestLogoutStoreFailureRollsBack(t *testing.T) {
	logs := captureSafeLogs(t)
	p := newPrototype(t)
	cookie, tokens := p.issueLogoutTokens(t)
	require.NoError(t, p.db.Exec(`CREATE FUNCTION reject_refresh_revoke() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'rollback-sentinel'; END; $$`).Error)
	require.NoError(t, p.db.Exec(`CREATE TRIGGER reject_refresh_revoke BEFORE UPDATE OF revoked_at ON oidc_refresh_families
		FOR EACH ROW EXECUTE FUNCTION reject_refresh_revoke()`).Error)
	logs.Reset()
	response := p.request(http.MethodGet, "/end_session?id_token_hint="+url.QueryEscape(tokens.IDToken), nil, cookie, "", "")
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.Empty(t, response.Header().Values("Set-Cookie"))
	require.NotContains(t, response.Body.String(), "rollback-sentinel")
	requireFailureCategory(t, logs, "logout_store_failed", "rollback-sentinel", tokens.IDToken)
	var sessions, refreshes int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_sessions").Scan(&sessions).Error)
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_tokens").Scan(&refreshes).Error)
	require.EqualValues(t, 1, sessions)
	require.EqualValues(t, 1, refreshes)
}

func TestParallelLogoutUsesSessionOnce(t *testing.T) {
	p := newPrototype(t)
	cookie, tokens := p.issueLogoutTokens(t)
	path := "/end_session?id_token_hint=" + url.QueryEscape(tokens.IDToken)
	results := make(chan int, 2)
	for range 2 {
		go func() { results <- p.request(http.MethodGet, path, nil, cookie, "", "").Code }()
	}
	statuses := []int{<-results, <-results}
	slices.Sort(statuses)
	require.Equal(t, []int{http.StatusFound, http.StatusBadRequest}, statuses)
	var sessions, refreshes int64
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_sessions").Scan(&sessions).Error)
	require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_refresh_families WHERE revoked_at IS NULL").Scan(&refreshes).Error)
	require.Zero(t, sessions)
	require.Zero(t, refreshes)
}

func requireFailureCategory(t *testing.T, logs *bytes.Buffer, category string, secrets ...string) {
	t.Helper()
	require.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("category="+category)), logs.String())
	for _, secret := range secrets {
		require.NotContains(t, logs.String(), secret)
	}
	t.Logf("safe log output:\n%s", strings.TrimSpace(logs.String()))
}

func TestSignInFailureLogsContainOnlyCategories(t *testing.T) {
	t.Run("invalid login request", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		logs.Reset()
		w := p.request(http.MethodGet, "/login?authRequestID=request-sentinel", nil, nil, "", "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		requireFailureCategory(t, logs, "login_request_invalid", "request-sentinel")
	})

	t.Run("PKCE required", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		logs.Reset()
		query, _ := authorizationQuery()
		query.Set("code_challenge", "challenge-sentinel")
		query.Set("code_challenge_method", "plain")
		w := p.request(http.MethodGet, "/authorize?"+query.Encode(), nil, nil, "", "")
		require.Equal(t, http.StatusFound, w.Code)
		requireFailureCategory(t, logs, "authorization_failed", "challenge-sentinel")
	})

	t.Run("Google state mismatch", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		state, _, _ := p.beginGoogle(t)
		logs.Reset()
		w := p.requestWithBrowser(http.MethodGet, "/auth/callback?state="+url.QueryEscape(state)+"&code=code-sentinel", nil, nil, nil, "", "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		requireFailureCategory(t, logs, "google_state_mismatch", "code-sentinel", state)
	})

	t.Run("Google exchange", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		state, cookie, _ := p.beginGoogle(t)
		logs.Reset()
		path := "/auth/callback?state=" + url.QueryEscape(state) + "&code=code-sentinel&email=person@example.com"
		w := p.request(http.MethodGet, path, nil, cookie, "", "")
		require.Equal(t, http.StatusUnauthorized, w.Code)
		requireFailureCategory(t, logs, "google_exchange_failed", "code-sentinel", "person@example.com", state)
	})

	t.Run("account link required", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		require.NoError(t, p.db.Exec("INSERT INTO users (id, email) VALUES (?, ?)", "00000000-0000-0000-0000-000000000001", "person@example.com").Error)
		state, cookie, _ := p.beginGoogle(t)
		logs.Reset()
		path := "/auth/callback?state=" + url.QueryEscape(state) + "&code=valid"
		w := p.request(http.MethodGet, path, nil, cookie, "", "")
		require.Equal(t, http.StatusForbidden, w.Code)
		requireFailureCategory(t, logs, "account_link_required", "person@example.com", state)
	})

	t.Run("token exchange", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		logs.Reset()
		w := p.exchange("code-sentinel", "verifier-sentinel", "app", "secret-sentinel", "http://127.0.0.1:8012/callback")
		require.NotEqual(t, http.StatusOK, w.Code)
		requireFailureCategory(t, logs, "token_exchange_failed", "code-sentinel", "verifier-sentinel", "secret-sentinel")
	})
}

func TestSuccessfulSignInDoesNotLogFailure(t *testing.T) {
	logs := captureSafeLogs(t)
	p := newPrototype(t)
	state, cookie, verifier := p.beginGoogle(t)
	logs.Reset()
	callback := p.request(http.MethodGet, "/auth/callback?state="+url.QueryEscape(state)+"&code=valid", nil, cookie, "", "")
	require.Equal(t, http.StatusFound, callback.Code)
	issued := p.request(http.MethodGet, pathFromLocation(t, callback), nil, nil, "", "")
	require.Equal(t, http.StatusFound, issued.Code)
	appURL, err := url.Parse(issued.Header().Get("Location"))
	require.NoError(t, err)
	exchange := p.exchange(appURL.Query().Get("code"), verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, exchange.Code, exchange.Body.String())
	require.NotContains(t, logs.String(), "sign_in_failed")
	t.Log("successful sign-in: no failure log")
}
