package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPSBrowserBindingCookieSignInAndLogout(t *testing.T) {
	p := newPrototypeWithIssuer(t, "https://identity.example")
	origin, err := url.Parse("https://identity.example/")
	require.NoError(t, err)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		requestURL, err := origin.Parse(path)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, requestURL.String(), nil)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		for _, cookie := range jar.Cookies(requestURL) {
			req.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		p.router.ServeHTTP(response, req)
		jar.SetCookies(requestURL, response.Result().Cookies())
		return response
	}

	authorize := get(authorizePathForCookieTest("app", "https://app.example/callback"))
	require.Equal(t, http.StatusFound, authorize.Code, authorize.Body.String())
	var binding *http.Cookie
	for _, cookie := range authorize.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "__Host-"+authBrowserCookie+"_") {
			binding = cookie
		}
	}
	require.NotNil(t, binding)
	require.True(t, binding.Secure)
	require.True(t, binding.HttpOnly)
	require.Equal(t, "/", binding.Path)
	require.Empty(t, binding.Domain)
	require.Equal(t, http.SameSiteLaxMode, binding.SameSite)
	require.Equal(t, 600, binding.MaxAge)
	require.Len(t, jar.Cookies(origin), 1)

	loginPath := pathFromLocation(t, authorize)
	// The non-HTTPS cookie name must not satisfy a production sign-in.
	wrongName := *binding
	wrongName.Name = strings.TrimPrefix(binding.Name, "__Host-")
	wrongNameRequest := p.requestWithBrowser(http.MethodGet, loginPath, nil, nil, &wrongName, "", "")
	require.Equal(t, http.StatusBadRequest, wrongNameRequest.Code)

	login := get(loginPath)
	require.Equal(t, http.StatusFound, login.Code, login.Body.String())
	googleURL, err := url.Parse(login.Header().Get("Location"))
	require.NoError(t, err)
	state := googleURL.Query().Get("state")
	require.NotEmpty(t, state)
	callback := get("/auth/callback?state=" + url.QueryEscape(state) + "&code=valid")
	require.Equal(t, http.StatusFound, callback.Code, callback.Body.String())
	finish := get(pathFromLocation(t, callback))
	require.Equal(t, http.StatusFound, finish.Code, finish.Body.String())
	require.Contains(t, finish.Header().Get("Location"), "https://app.example/callback")
	var cleared *http.Cookie
	for _, cookie := range finish.Result().Cookies() {
		if cookie.Name == binding.Name {
			cleared = cookie
		}
	}
	require.NotNil(t, cleared)
	require.True(t, cleared.Secure)
	require.Equal(t, "/", cleared.Path)
	require.Less(t, cleared.MaxAge, 0)
	for _, cookie := range jar.Cookies(origin) {
		require.NotEqual(t, binding.Name, cookie.Name)
	}

	// Exchange the real authorization code so logout uses a genuine ID token.
	appURL, err := url.Parse(finish.Header().Get("Location"))
	require.NoError(t, err)
	issued := p.exchange(appURL.Query().Get("code"), "a-very-long-pkce-verifier-created-by-the-client", "app", "secret", "https://app.example/callback")
	require.Equal(t, http.StatusOK, issued.Code, issued.Body.String())
	var tokens logoutTokens
	require.NoError(t, json.Unmarshal(issued.Body.Bytes(), &tokens))

	first := get(authorizePathForCookieTest("app", "https://app.example/callback"))
	second := get(authorizePathForCookieTest("app", "https://app.example/callback"))
	require.Equal(t, http.StatusFound, first.Code)
	require.Equal(t, http.StatusFound, second.Code)
	var pending []string
	for _, cookie := range jar.Cookies(origin) {
		if strings.HasPrefix(cookie.Name, "__Host-"+authBrowserCookie+"_") {
			pending = append(pending, cookie.Name)
		}
	}
	require.Len(t, pending, 2)

	rejected := get("/end_session")
	require.Equal(t, http.StatusBadRequest, rejected.Code)
	require.Empty(t, rejected.Result().Cookies())
	logout := get("/end_session?id_token_hint=" + url.QueryEscape(tokens.IDToken))
	require.Equal(t, http.StatusFound, logout.Code, logout.Body.String())
	var clearedPending []string
	for _, cookie := range logout.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "__Host-"+authBrowserCookie+"_") {
			require.True(t, cookie.Secure)
			require.Equal(t, "/", cookie.Path)
			require.Empty(t, cookie.Domain)
			require.Less(t, cookie.MaxAge, 0)
			clearedPending = append(clearedPending, cookie.Name)
		}
	}
	require.ElementsMatch(t, pending, clearedPending)
	for _, cookie := range jar.Cookies(origin) {
		require.False(t, strings.HasPrefix(cookie.Name, "__Host-"+authBrowserCookie+"_"))
	}
}
