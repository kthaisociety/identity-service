package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// A code in a GET URL must remain usable by the intended POST exchange.
func TestGETTokenCannotExchangeAuthorizationCode(t *testing.T) {
	p := newPrototype(t)
	code, _, verifier := p.signIn(t)
	query := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:8012/callback"}, "code_verifier": {verifier},
	}
	got := p.request(http.MethodGet, "/oauth/token?"+query.Encode(), nil, nil, "app", "secret")
	checkPOSTOnly(t, got)
	requireTokenCacheHeaders(t, got)
	if strings.Contains(got.Body.String(), `"access_token"`) {
		t.Error("GET returned an access token")
	}
	post := p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	if post.Code != http.StatusOK {
		t.Errorf("POST after GET returned HTTP %d; GET may have consumed the code", post.Code)
	}
}

// A GET request with a refresh token must neither rotate nor consume it.
func TestGETTokenCannotRefresh(t *testing.T) {
	p := newPrototype(t)
	_, issued := p.issueLogoutTokens(t)
	query := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}
	got := p.request(http.MethodGet, "/oauth/token?"+query.Encode(), nil, nil, "app", "secret")
	checkPOSTOnly(t, got)
	requireTokenCacheHeaders(t, got)
	if strings.Contains(got.Body.String(), `"access_token"`) {
		t.Error("GET returned an access token")
	}
	post := p.refresh(issued.RefreshToken, "app", "secret")
	if post.Code != http.StatusOK {
		t.Errorf("POST after GET returned HTTP %d; GET may have consumed the refresh token", post.Code)
	}
}

// A GET request with a refresh token must not revoke its family.
func TestGETRevokeCannotRevokeRefreshToken(t *testing.T) {
	p := newPrototype(t)
	_, issued := p.issueLogoutTokens(t)
	query := url.Values{"token": {issued.RefreshToken}, "token_type_hint": {"refresh_token"}}
	got := p.request(http.MethodGet, "/revoke?"+query.Encode(), nil, nil, "app", "secret")
	checkPOSTOnly(t, got)
	post := p.refresh(issued.RefreshToken, "app", "secret")
	if post.Code != http.StatusOK {
		t.Errorf("POST refresh after GET revoke returned HTTP %d; GET may have revoked the family", post.Code)
	}
}

func TestTokenRoutesRejectOtherMethods(t *testing.T) {
	p := newPrototype(t)
	for _, path := range []string{"/oauth/token", "/revoke"} {
		for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions} {
			t.Run(method+" "+path, func(t *testing.T) {
				response := p.request(method, path, nil, nil, "", "")
				checkPOSTOnly(t, response)
				if path == "/oauth/token" {
					requireTokenCacheHeaders(t, response)
				}
			})
		}
	}
}

func checkPOSTOnly(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusMethodNotAllowed {
		t.Errorf("HTTP status = %d, want 405", response.Code)
	}
	if allow := response.Header().Get("Allow"); allow != http.MethodPost {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestTokenResponsesAreNotCacheable(t *testing.T) {
	p := newPrototype(t)
	code, _, verifier := p.signIn(t)
	issued := p.exchange(code, verifier, "app", "secret", "http://127.0.0.1:8012/callback")
	require.Equal(t, http.StatusOK, issued.Code)
	requireTokenCacheHeaders(t, issued)
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)

	refreshed := p.refresh(tokens.RefreshToken, "app", "secret")
	require.Equal(t, http.StatusOK, refreshed.Code)
	requireTokenCacheHeaders(t, refreshed)

	invalid := p.refresh("not-issued", "app", "secret")
	require.Equal(t, http.StatusBadRequest, invalid.Code)
	requireTokenCacheHeaders(t, invalid)
}

func TestTokenCachePolicyOverridesProviderHeaders(t *testing.T) {
	ginTestMode()
	provider := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Pragma", "cache")
		w.WriteHeader(http.StatusOK)
	})
	router := gin.New()
	router.POST("/oauth/token", tokenEndpoint(provider))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))
	require.Equal(t, http.StatusOK, response.Code)
	requireTokenCacheHeaders(t, response)
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
}

func TestTokenRecoveryResponseIsNotCacheable(t *testing.T) {
	ginTestMode()
	provider := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("private-panic-value") })
	router := gin.New()
	router.Use(safeRecovery())
	router.POST("/oauth/token", withTokenCachePolicy(postOnly(tokenEndpoint(provider))))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))
	require.Equal(t, http.StatusInternalServerError, response.Code)
	requireTokenCacheHeaders(t, response)
	require.NotContains(t, response.Body.String(), "private-panic-value")
}

func requireTokenCacheHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, directive := range strings.Split(response.Header().Get("Cache-Control"), ",") {
		if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
			require.Equal(t, "no-cache", response.Header().Get("Pragma"))
			return
		}
	}
	t.Errorf("token response Cache-Control must include no-store; got %q", response.Header().Get("Cache-Control"))
}
