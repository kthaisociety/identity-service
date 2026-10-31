package safelog

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewDropsUntrustedErrorAttributes(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output)
	logger.Warn("request error",
		slog.Any("oidc_error", errors.New("token-sentinel")),
		slog.Group("details", slog.String("email", "person@example.com")),
		slog.String("url", "/auth/callback?code=code-sentinel"),
	)
	logger.Warn("sign_in_failed", "category", "google_exchange_failed", "listener", "public", "route", "/auth/callback", "status", 401)

	logText := output.String()
	for _, secret := range []string{"token-sentinel", "person@example.com", "code-sentinel", "oidc_error", "details", "url"} {
		require.NotContains(t, logText, secret)
	}
	require.True(t, strings.Contains(logText, "category=google_exchange_failed"), logText)
	require.Contains(t, logText, "status=401")
}
