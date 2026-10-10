// Package handlers is the HTTP layer: one router per listener (docs/adr/0003).
package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Deps struct {
	PingDB        func(ctx context.Context) error
	ServiceSecret string
}

// NewPublicRouter serves what browsers and apps reach from the internet: the sign-in flow. Nothing that
// manages users or holds admin rights belongs here.
func NewPublicRouter(d Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/health", health(d.PingDB))

	return r
}

// NewInternalRouter serves other KTHAIS services on the internal network only. Everything under /v1
// needs the service secret (docs/pcr/0003).
func NewInternalRouter(d Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/health", health(d.PingDB))

	v1 := r.Group("/v1", requireServiceSecret(d.ServiceSecret))
	_ = v1 // user and role management goes here

	return r
}

// requireServiceSecret rejects any request without the exact shared secret. An empty configured secret
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
