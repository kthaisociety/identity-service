package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func authorizePathForCookieTest(clientID, redirectURI string) string {
	digest := sha256.Sum256([]byte("a-very-long-pkce-verifier-created-by-the-client"))
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {"openid"}, "state": {"app-state"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	return "/authorize?" + query.Encode()
}

// Rejected OIDC requests must not leave a usable or orphaned browser cookie.
func TestAuthorizeSetsCookieOnlyAfterRequestIsStored(t *testing.T) {
	validPath := authorizePathForCookieTest("app", "http://127.0.0.1:8012/callback")
	for _, tc := range []struct {
		name, path string
	}{
		{"unknown client", authorizePathForCookieTest("unknown", "http://127.0.0.1:8012/callback")},
		{"unregistered redirect", authorizePathForCookieTest("app", "http://127.0.0.1:8012/unregistered")},
		{"empty later challenge", validPath + "&code_challenge="},
		{"mixed-case prompt", validPath + "&PROMPT=login"},
		{"fragment response", validPath + "&response_mode=fragment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPrototype(t)
			w := p.requestWithBrowser(http.MethodGet, tc.path, nil, nil, nil, "", "")
			for _, cookie := range w.Result().Cookies() {
				require.False(t, strings.HasPrefix(cookie.Name, authBrowserCookie+"_"), "rejected authorization set a request cookie")
			}
			require.NotContains(t, w.Header().Get("Location"), "/login?authRequestID=")
			var count int64
			require.NoError(t, p.db.Raw("SELECT count(*) FROM oidc_auth_requests").Scan(&count).Error)
			require.Zero(t, count, "rejected authorization stored a request")
		})
	}

	p := newPrototype(t)
	w := p.requestWithBrowser(http.MethodGet, validPath, nil, nil, nil, "", "")
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "/login?authRequestID=")
	var issued []*http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, authBrowserCookie+"_") {
			issued = append(issued, cookie)
		}
	}
	require.Len(t, issued, 1)
	require.Equal(t, 600, issued[0].MaxAge)
}

func TestAuthorizationCodeClearsOnlyItsRequestCookie(t *testing.T) {
	p := newPrototype(t)
	firstState, firstCookie, _ := p.beginGoogle(t)
	_, secondCookie, _ := p.beginGoogle(t)
	require.NotEqual(t, firstCookie.Name, secondCookie.Name)

	callback := p.requestWithBrowser(http.MethodGet, "/auth/callback?state="+url.QueryEscape(firstState)+"&code=valid", nil, nil, firstCookie, "", "")
	require.Equal(t, http.StatusFound, callback.Code)
	finish := p.requestWithBrowser(http.MethodGet, pathFromLocation(t, callback), nil, nil, firstCookie, "", "")
	require.Equal(t, http.StatusFound, finish.Code)
	var cleared []*http.Cookie
	for _, cookie := range finish.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, authBrowserCookie+"_") {
			cleared = append(cleared, cookie)
		}
	}
	require.Len(t, cleared, 1)
	require.Equal(t, firstCookie.Name, cleared[0].Name)
	require.Less(t, cleared[0].MaxAge, 0)
	// Finishing the first tab must not invalidate the second tab.
	secondLogin := p.requestWithBrowser(http.MethodGet, "/login?authRequestID="+strings.TrimPrefix(secondCookie.Name, authBrowserCookie+"_"), nil, nil, secondCookie, "", "")
	require.Equal(t, http.StatusFound, secondLogin.Code)
}

func TestLogoutClearsAllPendingSignInCookies(t *testing.T) {
	p := newPrototype(t)
	firstLogin, _ := p.authorize(t)
	firstCookie := p.browserCookie
	secondLogin, _ := p.authorize(t)
	secondCookie := p.browserCookie
	require.NotEqual(t, firstCookie.Name, secondCookie.Name)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	origin, err := url.Parse("http://127.0.0.1:8010/")
	require.NoError(t, err)
	jar.SetCookies(origin, []*http.Cookie{firstCookie, secondCookie})
	logout := requestWithJar(p, jar, "/end_session")
	var cleared []string
	for _, cookie := range logout.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, authBrowserCookie+"_") {
			require.Less(t, cookie.MaxAge, 0)
			cleared = append(cleared, cookie.Name)
		}
	}
	require.ElementsMatch(t, []string{firstCookie.Name, secondCookie.Name}, cleared)
	for _, cookie := range jar.Cookies(origin) {
		require.False(t, strings.HasPrefix(cookie.Name, authBrowserCookie+"_"))
	}
	require.Equal(t, http.StatusBadRequest, requestWithJar(p, jar, firstLogin).Code)
	require.Equal(t, http.StatusBadRequest, requestWithJar(p, jar, secondLogin).Code)
}
