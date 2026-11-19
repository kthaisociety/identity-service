package handlers

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPSBrowserBindingCookieCompletesSignIn(t *testing.T) {
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
}
