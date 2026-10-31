package oidcprovider

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"gorm.io/gorm"
)

// CreateAccessToken gives ZITADEL an ID and one-hour expiry for a signed access
// JWT. The JWT itself is not stored in Postgres.
func (s *Store) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	return uuid.NewString(), time.Now().UTC().Add(accessTokenLifetime), nil
}

// CreateAccessAndRefreshTokens issues a new opaque refresh token for
// /oauth/token. On refresh it removes the current token and stores the new
// token's hash in one transaction; ZITADEL signs the access JWT separately.
func (s *Store) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, current string) (string, string, time.Time, error) {
	clientRequest, ok := request.(interface {
		GetClientID() string
		GetAuthTime() time.Time
	})
	if !ok {
		return "", "", time.Time{}, errors.New("unsupported token request")
	}
	value, err := randomString()
	if err != nil {
		return "", "", time.Time{}, err
	}
	row := refreshToken{
		TokenHash: hash(value), UserID: request.GetSubject(), ClientID: clientRequest.GetClientID(),
		Scopes: strings.Join(request.GetScopes(), " "), AuthTime: clientRequest.GetAuthTime(),
		ExpiresAt: time.Now().UTC().Add(refreshTokenLifetime),
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if current != "" {
			result := tx.Delete(&refreshToken{}, "token_hash = ? AND user_id = ? AND client_id = ? AND expires_at > ?", hash(current), row.UserID, row.ClientID, time.Now().UTC())
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				return op.ErrInvalidRefreshToken
			}
		}
		return tx.Create(&row).Error
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	return uuid.NewString(), value, time.Now().UTC().Add(accessTokenLifetime), nil
}

// TokenRequestByRefreshToken loads an unexpired token's user, app, and scopes
// by hash for ZITADEL's /oauth/token refresh flow.
func (s *Store) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	var row refreshToken
	err := s.db.WithContext(ctx).First(&row, "token_hash = ? AND expires_at > ?", hash(value), time.Now().UTC()).Error
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	return &row, nil
}

// GetRefreshTokenInfo binds a presented token to its app and returns the stored
// token hash as the identifier ZITADEL uses when revoking it.
func (s *Store) GetRefreshTokenInfo(ctx context.Context, clientID, value string) (string, string, error) {
	var row refreshToken
	err := s.db.WithContext(ctx).First(&row, "token_hash = ? AND client_id = ? AND expires_at > ?", hash(value), clientID, time.Now().UTC()).Error
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return row.UserID, row.TokenHash, nil
}

// RevokeToken deletes an app's refresh-token row for /revoke. Issued access
// JWTs have no row to delete and remain valid until they expire.
func (s *Store) RevokeToken(ctx context.Context, tokenIDOrValue, userID, clientID string) *oidc.Error {
	// The library passes the stored token ID after a successful refresh-token
	// lookup, and the raw value if no lookup succeeded. Access-token IDs have no
	// stored row: those JWTs expire naturally after one hour.
	tokenHash := tokenIDOrValue
	if userID == "" {
		tokenHash = hash(tokenIDOrValue)
	}
	if err := s.db.WithContext(ctx).Delete(&refreshToken{}, "token_hash = ? AND client_id = ?", tokenHash, clientID).Error; err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}
