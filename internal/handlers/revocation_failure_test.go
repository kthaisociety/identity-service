package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRevokeDoesNotExposeDatabaseError(t *testing.T) {
	p := newPrototype(t)
	_, tokens := p.issueLogoutTokens(t)
	const constraint = "reject_revoke_with_private_marker"
	require.NoError(t, p.db.Exec("ALTER TABLE oidc_refresh_families ADD CONSTRAINT "+constraint+" CHECK (revoked_at IS NULL)").Error)
	restored := false
	t.Cleanup(func() {
		if !restored {
			require.NoError(t, p.db.Exec("ALTER TABLE oidc_refresh_families DROP CONSTRAINT IF EXISTS "+constraint).Error)
		}
	})
	form := url.Values{"token": {tokens.RefreshToken}, "token_type_hint": {"refresh_token"}}
	revoke := p.request(http.MethodPost, "/revoke", form, nil, "app", "secret")
	require.GreaterOrEqual(t, revoke.Code, http.StatusInternalServerError)
	require.JSONEq(t, `{"error":"server_error"}`, revoke.Body.String())
	require.NotContains(t, revoke.Body.String(), constraint, "database details must stay out of OAuth responses")
	require.NotContains(t, revoke.Body.String(), tokens.RefreshToken)

	refresh := p.refresh(tokens.RefreshToken, "app", "secret")
	require.Equal(t, http.StatusOK, refresh.Code, refresh.Body.String())
	var refreshed struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(refresh.Body.Bytes(), &refreshed))
	require.NotEmpty(t, refreshed.RefreshToken)
	require.NoError(t, p.db.Exec("ALTER TABLE oidc_refresh_families DROP CONSTRAINT "+constraint).Error)
	restored = true
	require.Equal(t, http.StatusOK, p.request(http.MethodPost, "/revoke", form, nil, "app", "secret").Code)
	require.Equal(t, http.StatusBadRequest, p.refresh(refreshed.RefreshToken, "app", "secret").Code)
}
