package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

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
