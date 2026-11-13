package oidcprovider

import (
	"context"
	"sync/atomic"
)

type refreshRequestStateKey struct{}

type refreshClaims struct {
	subject string
	email   string
	roles   []string
}

// RefreshRequestState lets the token endpoint distinguish a database outage
// from an invalid token. It also holds claims loaded before token rotation, so
// ZITADEL does not need another database read after committing the rotation.
type RefreshRequestState struct {
	failed atomic.Bool
	claims atomic.Pointer[refreshClaims]
}

// TrackRefreshRequest attaches request-local state to the token request.
func TrackRefreshRequest(ctx context.Context) (context.Context, *RefreshRequestState) {
	state := new(RefreshRequestState)
	return context.WithValue(ctx, refreshRequestStateKey{}, state), state
}

func (s *RefreshRequestState) StorageFailed() bool { return s.failed.Load() }

func refreshState(ctx context.Context) *RefreshRequestState {
	state, _ := ctx.Value(refreshRequestStateKey{}).(*RefreshRequestState)
	return state
}

func markRefreshStorageFailure(ctx context.Context) {
	if state := refreshState(ctx); state != nil {
		state.failed.Store(true)
	}
}

func cacheRefreshClaims(ctx context.Context, claims refreshClaims) {
	if state := refreshState(ctx); state != nil {
		state.claims.Store(&claims)
	}
}

func cachedRefreshClaims(ctx context.Context, userID string) (refreshClaims, bool) {
	if state := refreshState(ctx); state != nil {
		if claims := state.claims.Load(); claims != nil && claims.subject == userID {
			return *claims, true
		}
	}
	return refreshClaims{}, false
}
