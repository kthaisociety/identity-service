package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// The browser check and the OIDC provider must act on the same request ID.
// A POST body must not replace a different ID that passed a query-only check.
func TestAuthorizeCallbackRejectsConflictingBodyID(t *testing.T) {
	p := newPrototype(t)
	victimState, victimBrowser, _ := p.beginGoogle(t)
	victimCallback := p.requestWithBrowser(
		http.MethodGet, "/auth/callback?state="+url.QueryEscape(victimState)+"&code=valid",
		nil, nil, victimBrowser, "", "",
	)
	require.Equal(t, http.StatusFound, victimCallback.Code)
	victimFinish := pathFromLocation(t, victimCallback)
	victimURL, err := url.Parse(victimFinish)
	require.NoError(t, err)
	victimID := victimURL.Query().Get("id")
	require.NotEmpty(t, victimID)

	p.browserCookie = nil // a second browser with its own pending request
	attackerLogin, _ := p.authorize(t)
	attackerBrowser := p.browserCookie
	attackerURL, err := url.Parse(attackerLogin)
	require.NoError(t, err)
	attackerID := attackerURL.Query().Get("authRequestID")
	require.NotEmpty(t, attackerID)
	require.NotEqual(t, victimID, attackerID)

	mismatch := p.requestWithBrowser(
		http.MethodPost,
		"/authorize/callback?id="+url.QueryEscape(attackerID),
		url.Values{"id": {victimID}}, nil, attackerBrowser, "", "",
	)
	require.GreaterOrEqual(t, mismatch.Code, http.StatusBadRequest, mismatch.Body.String())
	require.Less(t, mismatch.Code, http.StatusInternalServerError, mismatch.Body.String())
	require.NotContains(t, mismatch.Header().Get("Location"), "127.0.0.1:8012/callback")

	// Rejected input must not consume the other browser's completed request.
	finish := p.requestWithBrowser(http.MethodGet, victimFinish, nil, nil, victimBrowser, "", "")
	require.Equal(t, http.StatusFound, finish.Code, finish.Body.String())
	require.Contains(t, finish.Header().Get("Location"), "127.0.0.1:8012/callback")
}

// Both authorization requests can leave the browser before either response
// sets a cookie. Replay the responses in either order through a real cookie
// jar: both tabs must remain able to finish with the cookies the browser kept.
func TestFirstSignInInTwoTabsKeepsBothRequestsUsable(t *testing.T) {
	for _, firstResponseLast := range []bool{false, true} {
		name := "first response then second"
		if firstResponseLast {
			name = "second response then first"
		}
		t.Run(name, func(t *testing.T) {
			p := newPrototype(t)
			verifier := "a-very-long-pkce-verifier-created-by-the-client"
			digest := sha256.Sum256([]byte(verifier))
			authorizePath := func(state string) string {
				query := url.Values{
					"response_type": {"code"}, "client_id": {"app"},
					"redirect_uri": {"http://127.0.0.1:8012/callback"},
					"scope":        {"openid"}, "state": {state},
					"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
					"code_challenge_method": {"S256"},
				}
				return "/authorize?" + query.Encode()
			}
			// Neither in-flight request includes the cookie from the other.
			first := p.requestWithBrowser(http.MethodGet, authorizePath("first-tab"), nil, nil, nil, "", "")
			second := p.requestWithBrowser(http.MethodGet, authorizePath("second-tab"), nil, nil, nil, "", "")
			require.Equal(t, http.StatusFound, first.Code, first.Body.String())
			require.Equal(t, http.StatusFound, second.Code, second.Body.String())

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			origin, err := url.Parse("http://127.0.0.1:8010/")
			require.NoError(t, err)
			if firstResponseLast {
				jar.SetCookies(origin, second.Result().Cookies())
				jar.SetCookies(origin, first.Result().Cookies())
			} else {
				jar.SetCookies(origin, first.Result().Cookies())
				jar.SetCookies(origin, second.Result().Cookies())
			}

			loginPaths := []string{pathFromLocation(t, first), pathFromLocation(t, second)}
			states := make([]string, 0, len(loginPaths))
			for _, path := range loginPaths {
				login := requestWithJar(p, jar, path)
				require.Equal(t, http.StatusFound, login.Code, login.Body.String())
				googleURL, err := url.Parse(login.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "google.example", googleURL.Host)
				state := googleURL.Query().Get("state")
				require.NotEmpty(t, state)
				states = append(states, state)
			}

			for _, state := range states {
				callback := requestWithJar(p, jar, "/auth/callback?state="+url.QueryEscape(state)+"&code=valid")
				require.Equal(t, http.StatusFound, callback.Code, callback.Body.String())
				finish := requestWithJar(p, jar, pathFromLocation(t, callback))
				require.Equal(t, http.StatusFound, finish.Code, finish.Body.String())
				appURL, err := url.Parse(finish.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "127.0.0.1:8012", appURL.Host)
				require.NotEmpty(t, appURL.Query().Get("code"))
			}
		})
	}
}

func requestWithJar(p *prototype, jar http.CookieJar, path string) *httptest.ResponseRecorder {
	requestURL, _ := url.Parse("http://127.0.0.1:8010" + path)
	req := httptest.NewRequest(http.MethodGet, requestURL.String(), nil)
	for _, cookie := range jar.Cookies(requestURL) {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	p.router.ServeHTTP(recorder, req)
	jar.SetCookies(requestURL, recorder.Result().Cookies())
	return recorder
}
