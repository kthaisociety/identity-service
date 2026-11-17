package oidcprovider

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// These write methods must enforce the binding themselves. A caller that
// forgets a preceding read must not be able to change another browser's
// authorization request.
func TestAuthorizationRequestWritesRequireStartingBrowser(t *testing.T) {
	t.Run("BeginGoogle", func(t *testing.T) {
		s, id, right, rejected := boundRequestForWriteTest(t)
		for _, ctx := range rejected {
			_, err := s.BeginGoogle(ctx, id)
			require.Error(t, err)
			row := requestRowForWriteTest(t, s, id)
			require.Nil(t, row.GoogleStateHash)
			require.False(t, row.IsDone)
		}
		state, err := s.BeginGoogle(right, id)
		require.NoError(t, err)
		require.NotEmpty(t, state)
	})

	t.Run("CompleteGoogle", func(t *testing.T) {
		s, id, right, rejected := boundRequestForWriteTest(t)
		state, err := s.BeginGoogle(right, id)
		require.NoError(t, err)
		for _, ctx := range rejected {
			_, _, err := s.CompleteGoogle(ctx, state, "00000000-0000-0000-0000-000000000001")
			require.Error(t, err)
			row := requestRowForWriteTest(t, s, id)
			require.False(t, row.IsDone)
			require.NotNil(t, row.GoogleStateHash, "rejected callback must not consume the Google state")
		}
		gotID, _, err := s.CompleteGoogle(right, state, "00000000-0000-0000-0000-000000000001")
		require.NoError(t, err)
		require.Equal(t, id, gotID)
	})

	t.Run("CompleteSessionLogin", func(t *testing.T) {
		s, id, right, rejected := boundRequestForWriteTest(t)
		for _, ctx := range rejected {
			err := s.CompleteSessionLogin(ctx, id, "00000000-0000-0000-0000-000000000001", time.Now().UTC())
			require.Error(t, err)
			require.False(t, requestRowForWriteTest(t, s, id).IsDone)
		}
		err := s.CompleteSessionLogin(right, id, "00000000-0000-0000-0000-000000000001", time.Now().UTC())
		require.NoError(t, err)
		require.True(t, requestRowForWriteTest(t, s, id).IsDone)
	})

	t.Run("SaveAuthCode", func(t *testing.T) {
		s, id, right, rejected := boundRequestForWriteTest(t)
		err := s.CompleteSessionLogin(right, id, "00000000-0000-0000-0000-000000000001", time.Now().UTC())
		require.NoError(t, err)
		for _, ctx := range rejected {
			err := s.SaveAuthCode(ctx, id, "code")
			require.Error(t, err)
			require.Nil(t, requestRowForWriteTest(t, s, id).CodeHash)
		}
		require.NoError(t, s.SaveAuthCode(right, id, "code"))
		require.NotNil(t, requestRowForWriteTest(t, s, id).CodeHash)
	})

	t.Run("AuthRequestByID", func(t *testing.T) {
		s, id, right, rejected := boundRequestForWriteTest(t)
		require.NoError(t, s.CompleteSessionLogin(right, id, "00000000-0000-0000-0000-000000000001", time.Now().UTC()))
		for _, ctx := range rejected {
			_, err := s.AuthRequestByID(ctx, id)
			require.Error(t, err)
		}
		request, err := s.AuthRequestByID(right, id)
		require.NoError(t, err)
		require.Equal(t, id, request.GetID())
	})
}

func boundRequestForWriteTest(t *testing.T) (*Store, string, context.Context, []context.Context) {
	t.Helper()
	s := testStore(t)
	right := WithBrowserBinding(context.Background(), "starting-browser")
	wrong := WithBrowserBinding(context.Background(), "different-browser")
	request, err := s.CreateAuthRequest(right, &oidc.AuthRequest{
		ClientID: "app", RedirectURI: "http://127.0.0.1:8012/callback",
		CodeChallenge: "challenge", CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"openid"},
	}, "")
	require.NoError(t, err)
	return s, request.GetID(), right, []context.Context{context.Background(), wrong}
}

func requestRowForWriteTest(t *testing.T, s *Store, id string) authRequest {
	t.Helper()
	var row authRequest
	require.NoError(t, s.db.First(&row, "id = ?", id).Error)
	return row
}
