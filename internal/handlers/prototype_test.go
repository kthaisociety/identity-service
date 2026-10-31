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

type fakeGoogle struct{ calls int }

func (g *fakeGoogle) AuthURL(state string) string {
	return "https://google.example/authorize?state=" + url.QueryEscape(state)
}
func (g *fakeGoogle) Exchange(_ context.Context, code string) (googleauth.Identity, error) {
	g.calls++
	if code != "valid" {
		return googleauth.Identity{}, context.Canceled
	}
	return googleauth.Identity{Subject: "google-sub", Email: "person@example.com"}, nil
}

type prototype struct {
	router http.Handler
	db     *gorm.DB
	google *fakeGoogle
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
	if cookie != nil {
		req.AddCookie(cookie)
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

func (p *prototype) authorize(t *testing.T) (string, string) {
	t.Helper()
	verifier := "a-very-long-pkce-verifier-created-by-the-client"
	digest := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {"http://127.0.0.1:8012/callback"},
		"scope": {"openid email offline_access"}, "state": {"app-state"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	w := p.request(http.MethodGet, "/authorize?"+query.Encode(), nil, nil, "", "")
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
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
	stateCookies := login.Result().Cookies()
	require.Len(t, stateCookies, 1)
	require.Equal(t, googleStateCookie, stateCookies[0].Name)
	require.True(t, stateCookies[0].HttpOnly)
	require.Equal(t, "/auth/callback", stateCookies[0].Path)
	require.Equal(t, http.SameSiteLaxMode, stateCookies[0].SameSite)
	return state, stateCookies[0], verifier
}

func (p *prototype) signIn(t *testing.T) (string, *http.Cookie, string) {
	t.Helper()
	state, stateCookie, verifier := p.beginGoogle(t)
	callbackPath := "/auth/callback?state=" + url.QueryEscape(state) + "&code=valid"
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodGet, callbackPath, nil, nil, "", "").Code)
	wrongState := *stateCookie
	wrongState.Value = "wrong"
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodGet, callbackPath, nil, &wrongState, "", "").Code)
	callback := p.request(http.MethodGet, callbackPath, nil, stateCookie, "", "")
	require.Equal(t, http.StatusFound, callback.Code, callback.Body.String())
	require.Equal(t, http.StatusBadRequest, p.request(http.MethodGet, callbackPath, nil, stateCookie, "", "").Code)
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
	for _, control := range []string{"prompt=login", "max_age=0"} {
		unsupported := p.request(http.MethodGet, "/authorize?"+control, nil, nil, "", "")
		require.Equal(t, http.StatusBadRequest, unsupported.Code)
		require.Contains(t, unsupported.Body.String(), "not supported")
	}

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

	logout := p.request(http.MethodGet, "/end_session?client_id=app&post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A8012%2F", nil, cookie, "", "")
	require.Equal(t, http.StatusFound, logout.Code, logout.Body.String())
	require.Equal(t, "http://127.0.0.1:8012/", logout.Header().Get("Location"))
	loginPath, _ = p.authorize(t)
	login = p.request(http.MethodGet, loginPath, nil, cookie, "", "")
	require.Equal(t, http.StatusFound, login.Code)
	require.Contains(t, login.Header().Get("Location"), "google.example/authorize")
}

func TestAuthorizationRejectsWrongPKCEVerifier(t *testing.T) {
	p := newPrototype(t)
	code, _, verifier := p.signIn(t)
	require.NotEqual(t, http.StatusOK, p.exchange(code, verifier+"wrong", "app", "secret", "http://127.0.0.1:8012/callback").Code)
	// A failed exchange cannot turn the same code into a token later.
	require.NotEqual(t, http.StatusOK, p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback").Code)
}

func TestLogoutWithIDTokenHintEndsSessionAndRefresh(t *testing.T) {
	p := newPrototype(t)
	code, cookie, verifier := p.signIn(t)
	issued := p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, issued.Code)
	var tokens struct {
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &tokens))
	query := url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {"http://127.0.0.1:8012/"}}
	logout := p.request(http.MethodGet, "/end_session?"+query.Encode(), nil, cookie, "", "")
	require.Equal(t, http.StatusFound, logout.Code, logout.Body.String())
	require.Equal(t, "http://127.0.0.1:8012/", logout.Header().Get("Location"))
	loginPath, _ := p.authorize(t)
	login := p.request(http.MethodGet, loginPath, nil, cookie, "", "")
	require.Contains(t, login.Header().Get("Location"), "google.example/authorize")
	require.NotEqual(t, http.StatusOK, p.request(http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken},
	}, nil, "app", "secret").Code)
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
		w := p.request(http.MethodGet, "/authorize?code_challenge=challenge-sentinel&code_challenge_method=plain", nil, nil, "", "")
		require.Equal(t, http.StatusBadRequest, w.Code)
		requireFailureCategory(t, logs, "authorization_pkce_required", "challenge-sentinel")
	})

	t.Run("Google state mismatch", func(t *testing.T) {
		logs := captureSafeLogs(t)
		p := newPrototype(t)
		state, _, _ := p.beginGoogle(t)
		logs.Reset()
		w := p.request(http.MethodGet, "/auth/callback?state="+url.QueryEscape(state)+"&code=code-sentinel", nil, nil, "", "")
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
