// Package handlers is the HTTP layer: one router per listener (docs/adr/0003).
package handlers

import (
	"context"
	"crypto/subtle"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/kthaisociety/identity-service/internal/googleauth"
	"github.com/kthaisociety/identity-service/internal/oidcprovider"
)

// Deps holds the services used by the public and internal routers.
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
// manages users or holds admin rights belongs here.
func NewPublicRouter(d Deps) *gin.Engine {
	r := gin.New()
	// Request URLs and headers can contain codes or credentials.
	r.Use(safeRecovery())

	r.GET("/health", health(d.PingDB))
	if d.Provider != nil {
		r.GET("/login", login(d))
		r.GET("/auth/callback", googleCallback(d))
		r.GET("/authorize", func(c *gin.Context) {
			// The login UI does not yet implement forced reauthentication or
			// silent login. Reject these controls instead of silently ignoring them.
			if c.Request.URL.Query().Has("prompt") || c.Request.URL.Query().Has("max_age") {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "prompt and max_age are not supported"})
				return
			}
			if c.Query("code_challenge") == "" || c.Query("code_challenge_method") != "S256" {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "PKCE S256 required"})
				return
			}
			d.Provider.ServeHTTP(c.Writer, c.Request)
		})
		r.GET("/end_session", endSession(d))
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
	sessionCookie     = "identity_session"
	googleStateCookie = "identity_google_state"
)

func identityCookie(d Deps, name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: strings.HasPrefix(d.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
}

func login(d Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Query("authRequestID")
		request, err := d.AuthStore.AuthRequestByID(c.Request.Context(), id)
		if err != nil || request.Done() {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid login request"})
			return
		}
		if cookie, err := c.Cookie(sessionCookie); err == nil {
			if userID, authTime, err := d.AuthStore.SessionUser(c.Request.Context(), cookie); err == nil {
				if err := d.AuthStore.CompleteSessionLogin(c.Request.Context(), id, userID, authTime); err != nil {
					c.AbortWithStatus(http.StatusInternalServerError)
					return
				}
				c.Redirect(http.StatusFound, d.AuthCallbackURL(c.Request.Context(), id))
				return
			}
		}
		state, err := d.AuthStore.BeginGoogle(c.Request.Context(), id)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		http.SetCookie(c.Writer, identityCookie(d, googleStateCookie, state, "/auth/callback", int(oidcprovider.AuthRequestLifetime.Seconds())))
		c.Redirect(http.StatusFound, d.Google.AuthURL(state))
	}
}

func googleCallback(d Deps) gin.HandlerFunc {
	return func(c *gin.Context) {
		state, code := c.Query("state"), c.Query("code")
		if state == "" || code == "" {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		browserState, err := c.Cookie(googleStateCookie)
		if err != nil || subtle.ConstantTimeCompare([]byte(browserState), []byte(state)) != 1 {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		http.SetCookie(c.Writer, identityCookie(d, googleStateCookie, "", "/auth/callback", -1))
		if _, err := d.AuthStore.RequestIDForGoogleState(c.Request.Context(), state); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		identity, err := d.Google.Exchange(c.Request.Context(), code)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		userID, err := d.AuthStore.FindOrCreateGoogleUser(c.Request.Context(), identity.Subject, identity.Email)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		id, authTime, err := d.AuthStore.CompleteGoogle(c.Request.Context(), state, userID)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		value, err := d.AuthStore.CreateSession(c.Request.Context(), userID, authTime)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		http.SetCookie(c.Writer, identityCookie(d, sessionCookie, value, "/", int(oidcprovider.SessionLifetime.Seconds())))
		c.Redirect(http.StatusFound, d.AuthCallbackURL(c.Request.Context(), id))
	}
}

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

// NewInternalRouter serves other KTHAIS services on the internal network only. Everything under /v1
// needs the service secret (docs/pcr/0003).
func NewInternalRouter(d Deps) *gin.Engine {
	r := gin.New()
	r.Use(safeRecovery())

	r.GET("/health", health(d.PingDB))

	// Every route attached to v1 is protected by the requireServiceSecret middleware.
	v1 := r.Group("/v1", requireServiceSecret(d.ServiceSecret))
	_ = v1 // user and role management goes here

	// What will live under v1 later: Internal APIs called only by other microservices (e.g. fetching private user data, changing roles, or creating Google Workspace accounts).

	return r
}

func safeRecovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, _ any) {
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

// Handler, not a middleware. Returns json response to caller.
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
