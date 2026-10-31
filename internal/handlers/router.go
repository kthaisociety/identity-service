// Package handlers is the HTTP layer: one router per listener (docs/adr/0003).
package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kthaisociety/identity-service/internal/googleauth"
	"github.com/kthaisociety/identity-service/internal/oidcprovider"
)

// Deps holds the services used by the public and internal routers.
// Provider runs OIDC with apps; AuthStore holds KTHAIS state; Google verifies the person;
// AuthCallbackURL returns to that protocol after login; Issuer is identity's configured public origin.
type Deps struct {
	PingDB        func(ctx context.Context) error
	ServiceSecret string
	Provider      http.Handler
	AuthStore     *oidcprovider.Store
	Google        interface {
		AuthURL(string) string
		Exchange(context.Context, string) (googleauth.Identity, error)
	}
	AuthCallbackURL func(context.Context, string) string
	Issuer          string
}

// NewPublicRouter serves what browsers and apps reach from the internet: the sign-in flow. Nothing that
// manages users or holds admin rights belongs here. ZITADEL handles OIDC routes;
// our handlers identify the user through an existing session or Google.
func NewPublicRouter(d Deps) *gin.Engine {
	r := gin.New()
	// Request URLs and headers can contain codes or credentials.
	r.Use(failureLogging("public"), safeRecovery())

	r.GET("/health", health(d.PingDB))
	if d.Provider != nil {
		r.GET("/authorize", func(c *gin.Context) {
			// The login UI does not yet implement forced reauthentication or
			// silent login. Reject these controls instead of silently ignoring them.
			if c.Request.URL.Query().Has("prompt") || c.Request.URL.Query().Has("max_age") {
				markFailure(c, "authorization_unsupported")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "prompt and max_age are not supported"})
				return
			}
			if c.Query("code_challenge") == "" || c.Query("code_challenge_method") != "S256" {
				markFailure(c, "authorization_pkce_required")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "PKCE S256 required"})
				return
			}
			// ZITADEL validates and stores the app request through AuthStore. On
			// success it redirects the browser to /login?authRequestID=...
			d.Provider.ServeHTTP(c.Writer, c.Request)
		})
		r.GET("/login", login(d))
		r.GET("/auth/callback", googleCallback(d))

		r.GET("/end_session", endSession(d))
		// These OIDC routes need no identity handler logic; Gin passes each
		// request to the provider's handler for that path.
		for _, path := range []string{
			"/.well-known/openid-configuration", "/authorize/callback", "/oauth/token",
			"/keys", "/userinfo", "/oauth/introspect", "/revoke",
		} {
			r.Any(path, gin.WrapH(d.Provider))
		}
		r.GET("/signed-out", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	}

	return r
}

const (
	sessionCookie      = "identity_session"
	googleStateCookie  = "identity_google_state"
	failureCategoryKey = "failure_category"
)

// markFailure records only a fixed category. The middleware emits the event
// after the handler has chosen its response status.
func markFailure(c *gin.Context, category string) {
	c.Set(failureCategoryKey, category)
}

// reject sends a response and leaves a fixed category for failureLogging.
func reject(c *gin.Context, status int, category string) {
	markFailure(c, category)
	c.AbortWithStatus(status)
}

// failureLogging emits one category-only record after a failed sign-in route.
// It also catches OIDC errors returned as redirects instead of HTTP 4xx.
func failureLogging(listener string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		status := c.Writer.Status()
		if status < http.StatusBadRequest && !oidcErrorRedirect(c, status) {
			return
		}
		category, _ := c.Get(failureCategoryKey)
		name, _ := category.(string)
		if name == "" {
			name = providerFailureCategory(c.FullPath())
		}
		if name == "" {
			return
		}
		level := slog.LevelWarn
		if status >= http.StatusInternalServerError {
			level = slog.LevelError
		}
		slog.LogAttrs(c.Request.Context(), level, "sign_in_failed",
			slog.String("category", name),
			slog.String("listener", listener),
			slog.String("route", c.FullPath()),
			slog.Int("status", status),
		)
	}
}

// oidcErrorRedirect detects a provider error in a 3xx Location without logging
// the URL, which may contain codes, state, or other request values.
func oidcErrorRedirect(c *gin.Context, status int) bool {
	if status < http.StatusMultipleChoices || status >= http.StatusBadRequest || providerFailureCategory(c.FullPath()) == "" {
		return false
	}
	redirect, err := url.Parse(c.Writer.Header().Get("Location"))
	if err != nil {
		return false
	}
	if redirect.Query().Has("error") {
		return true
	}
	fragment, err := url.ParseQuery(redirect.Fragment)
	return err == nil && fragment.Has("error")
}

// providerFailureCategory maps library-owned routes to fixed log categories.
func providerFailureCategory(route string) string {
	switch route {
	case "/authorize":
		return "authorization_failed"
	case "/authorize/callback":
		return "authorization_callback_failed"
	case "/oauth/token":
		return "token_exchange_failed"
	default:
		return ""
	}
}

// identityCookie applies the browser cookie settings shared by SSO and Google
// state; production cookies are Secure when the configured issuer uses HTTPS.
func identityCookie(d Deps, name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: strings.HasPrefix(d.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
}

// login resumes the authorization request created by ZITADEL at /authorize.
// It first rejects unknown, expired, or already-completed requests.
// An already valid identity session completes the request and returns to ZITADEL's
// /authorize/callback. Otherwise, it binds a new Google state to this request
// and browser, then redirects the browser to Google for sign-in.
func login(d Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Query("authRequestID")
		request, err := d.AuthStore.AuthRequestByID(c.Request.Context(), id)
		if err != nil || request.Done() {
			markFailure(c, "login_request_invalid")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid login request"})
			return
		}
		if cookie, err := c.Cookie(sessionCookie); err == nil {
			if userID, authTime, err := d.AuthStore.SessionUser(c.Request.Context(), cookie); err == nil {
				if err := d.AuthStore.CompleteSessionLogin(c.Request.Context(), id, userID, authTime); err != nil {
					reject(c, http.StatusInternalServerError, "session_store_failed")
					return
				}
				// The browser returns to ZITADEL to finish this app's request.
				c.Redirect(http.StatusFound, d.AuthCallbackURL(c.Request.Context(), id))
				return
			}
		}
		state, err := d.AuthStore.BeginGoogle(c.Request.Context(), id)
		if err != nil {
			reject(c, http.StatusInternalServerError, "google_state_store_failed")
			return
		}
		http.SetCookie(c.Writer, identityCookie(d, googleStateCookie, state, "/auth/callback", int(oidcprovider.AuthRequestLifetime.Seconds())))
		c.Redirect(http.StatusFound, d.Google.AuthURL(state))
	}
}

// googleCallback handles Google's redirect to /auth/callback after sign-in.
// It checks the browser-bound state, exchanges Google's code, and verifies the
// returned identity before finding or creating the KTHAIS user. On success it
// completes the pending authorization request, creates an identity session,
// and redirects the browser to ZITADEL's /authorize/callback.
func googleCallback(d Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		state, code := c.Query("state"), c.Query("code")
		if state == "" || code == "" {
			reject(c, http.StatusBadRequest, "google_callback_invalid")
			return
		}
		browserState, err := c.Cookie(googleStateCookie)
		if err != nil || subtle.ConstantTimeCompare([]byte(browserState), []byte(state)) != 1 {
			reject(c, http.StatusBadRequest, "google_state_mismatch")
			return
		}
		http.SetCookie(c.Writer, identityCookie(d, googleStateCookie, "", "/auth/callback", -1))
		if _, err := d.AuthStore.RequestIDForGoogleState(c.Request.Context(), state); err != nil {
			reject(c, http.StatusBadRequest, "google_state_invalid")
			return
		}
		// This is Google's code; ZITADEL creates the separate app code later.
		identity, err := d.Google.Exchange(c.Request.Context(), code)
		if err != nil {
			reject(c, http.StatusUnauthorized, "google_exchange_failed")
			return
		}
		userID, err := d.AuthStore.FindOrCreateGoogleUser(c.Request.Context(), identity.Subject, identity.Email)
		if err != nil {
			category := "user_store_failed"
			if errors.Is(err, oidcprovider.ErrAccountLinkRequired) {
				category = "account_link_required"
			}
			reject(c, http.StatusForbidden, category)
			return
		}
		id, authTime, err := d.AuthStore.CompleteGoogle(c.Request.Context(), state, userID)
		if err != nil {
			reject(c, http.StatusBadRequest, "google_state_complete_failed")
			return
		}
		value, err := d.AuthStore.CreateSession(c.Request.Context(), userID, authTime)
		if err != nil {
			reject(c, http.StatusInternalServerError, "session_store_failed")
			return
		}
		http.SetCookie(c.Writer, identityCookie(d, sessionCookie, value, "/", int(oidcprovider.SessionLifetime.Seconds())))
		c.Redirect(http.StatusFound, d.AuthCallbackURL(c.Request.Context(), id))
	}
}

// endSession clears our browser session, then lets ZITADEL validate the logout
// request and redirect to an allowed app or /signed-out.
func endSession(d Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		if value, err := c.Cookie(sessionCookie); err == nil {
			_ = d.AuthStore.EndSession(c.Request.Context(), value)
		}
		http.SetCookie(c.Writer, identityCookie(d, sessionCookie, "", "/", -1))
		http.SetCookie(c.Writer, identityCookie(d, googleStateCookie, "", "/auth/callback", -1))
		d.Provider.ServeHTTP(c.Writer, c.Request)
	}
}

// NewInternalRouter serves other KTHAIS services on the internal network only.
// /v1 requires the service secret but has no business routes in this prototype.
func NewInternalRouter(d Deps) *gin.Engine {
	r := gin.New()
	r.Use(failureLogging("internal"), safeRecovery())

	r.GET("/health", health(d.PingDB))

	// Every route attached to v1 is protected by the requireServiceSecret middleware.
	v1 := r.Group("/v1", requireServiceSecret(d.ServiceSecret))
	_ = v1 // user and role management goes here

	// What will live under v1 later: Internal APIs called only by other microservices (e.g. fetching private user data, changing roles, or creating Google Workspace accounts).

	return r
}

// safeRecovery returns 500 and records only the panic category; the panic value
// and stack are discarded because they can contain credentials or user data.
func safeRecovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
		markFailure(c, "panic_recovered")
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// requireServiceSecret middleware. Rejects any request without the exact shared secret. An empty configured secret
// rejects everything: it never means "no secret required".
func requireServiceSecret(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		provided := c.GetHeader("X-Service-Secret")
		if secret == "" || provided == "" ||
			subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}

// health reports whether the listener can reach Postgres; both listeners use it.
func health(pingDB func(ctx context.Context) error) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := pingDB(c.Request.Context()); err != nil {
			_ = c.Error(err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"service": "identity-service", "status": "unhealthy"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"service": "identity-service", "status": "healthy"})
	}
}
