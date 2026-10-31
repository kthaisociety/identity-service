package handlers

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/kthaisociety/identity-service/internal/safelog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureSafeLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	previous := slog.Default()
	output := new(bytes.Buffer)
	slog.SetDefault(safelog.New(output))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return output
}

func healthyDB(context.Context) error { return nil }

func get(r http.Handler, path, secret string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if secret != "" {
		req.Header.Set("X-Service-Secret", secret)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHealthOnBothListeners(t *testing.T) {
	gin.SetMode(gin.TestMode)
	d := Deps{PingDB: healthyDB, ServiceSecret: "s3cret"}

	assert.Equal(t, http.StatusOK, get(NewPublicRouter(d), "/health", "").Code)
	assert.Equal(t, http.StatusOK, get(NewInternalRouter(d), "/health", "").Code)
}

func TestHealthReportsAnUnreachableDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	d := Deps{PingDB: func(context.Context) error { return errors.New("connection refused") }}

	w := get(NewPublicRouter(d), "/health", "")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotContains(t, w.Body.String(), "connection refused")
}

func TestServiceSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newRouter := func(secret string) *gin.Engine {
		r := gin.New()
		r.GET("/v1/ping", requireServiceSecret(secret), func(c *gin.Context) { c.Status(http.StatusOK) })
		return r
	}

	r := newRouter("s3cret")
	assert.Equal(t, http.StatusUnauthorized, get(r, "/v1/ping", "").Code)
	assert.Equal(t, http.StatusUnauthorized, get(r, "/v1/ping", "wrong").Code)
	assert.Equal(t, http.StatusOK, get(r, "/v1/ping", "s3cret").Code)

	// An empty configured secret rejects everything.
	assert.Equal(t, http.StatusUnauthorized, get(newRouter(""), "/v1/ping", "anything").Code)
}

func TestRecoveredPanicLogsOnlyItsCategory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logs := captureSafeLogs(t)
	r := NewInternalRouter(Deps{PingDB: func(context.Context) error { panic("panic-secret-sentinel") }})

	w := get(r, "/health?code=code-secret-sentinel&email=person@example.com", "")
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("category=panic_recovered")))
	require.Contains(t, logs.String(), "listener=internal")
	for _, secret := range []string{"panic-secret-sentinel", "code-secret-sentinel", "person@example.com"} {
		require.NotContains(t, logs.String(), secret)
	}
	t.Logf("safe log output:\n%s", logs.String())
}

func TestOIDCErrorRedirectLogsWithoutItsURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logs := captureSafeLogs(t)
	r := gin.New()
	r.Use(failureLogging("public"), safeRecovery())
	r.GET("/authorize", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "https://app.example/callback?error=access_denied&state=state-secret-sentinel")
	})

	w := get(r, "/authorize?code=code-secret-sentinel", "")
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("category=authorization_failed")))
	for _, secret := range []string{"state-secret-sentinel", "code-secret-sentinel", "app.example", "access_denied"} {
		require.NotContains(t, logs.String(), secret)
	}
	t.Logf("safe log output:\n%s", logs.String())
}
