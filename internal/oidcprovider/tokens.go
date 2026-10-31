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

// These methods implement op.AuthStorage's token persistence and revocation contract.
func (s *Store) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	return uuid.NewString(), time.Now().UTC().Add(accessTokenLifetime), nil
}

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

func (s *Store) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	var row refreshToken
	err := s.db.WithContext(ctx).First(&row, "token_hash = ? AND expires_at > ?", hash(value), time.Now().UTC()).Error
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	return &row, nil
}

func (s *Store) GetRefreshTokenInfo(ctx context.Context, clientID, value string) (string, string, error) {
	var row refreshToken
	err := s.db.WithContext(ctx).First(&row, "token_hash = ? AND client_id = ? AND expires_at > ?", hash(value), clientID, time.Now().UTC()).Error
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return row.UserID, row.TokenHash, nil
}

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
