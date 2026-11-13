package handlers

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kthaisociety/identity-service/internal/oidcprovider"
)

// tokenResponseBuffer holds the provider's small JSON response until we know
// whether a refresh lookup failed in Postgres.
type tokenResponseBuffer struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (w *tokenResponseBuffer) Header() http.Header { return w.header }

func (w *tokenResponseBuffer) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *tokenResponseBuffer) Write(value []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(value)
}

// tokenEndpoint delegates OAuth to ZITADEL. The library maps every refresh
// lookup error to invalid_grant, so request-local storage failures replace
// that response with a retryable error. Other provider 5xx bodies are also
// replaced because they can contain raw database error descriptions.
func tokenEndpoint(provider http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, refreshState := oidcprovider.TrackRefreshRequest(c.Request.Context())
		buffered := &tokenResponseBuffer{header: make(http.Header)}
		provider.ServeHTTP(buffered, c.Request.WithContext(ctx))

		status := buffered.status
		if status == 0 {
			status = http.StatusOK
		}
		if refreshState.StorageFailed() {
			markFailure(c, "token_store_failed")
			tokenServerError(c, http.StatusServiceUnavailable)
			return
		}
		if status >= http.StatusInternalServerError {
			tokenServerError(c, status)
			return
		}
		for name, values := range buffered.header {
			c.Writer.Header()[name] = append([]string(nil), values...)
		}
		c.Status(status)
		_, _ = c.Writer.Write(buffered.body.Bytes())
	}
}

func tokenServerError(c *gin.Context, status int) {
	c.Header("Cache-Control", "no-store")
	c.AbortWithStatusJSON(status, gin.H{"error": "server_error"})
}
