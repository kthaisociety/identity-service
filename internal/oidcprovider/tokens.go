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
	"gorm.io/gorm/clause"
)

// CreateAccessToken gives ZITADEL an ID and one-hour expiry for a signed access
// JWT. The JWT itself is not stored in Postgres.
func (s *Store) CreateAccessToken(context.Context, op.TokenRequest) (string, time.Time, error) {
	return uuid.NewString(), time.Now().UTC().Add(accessTokenLifetime), nil
}

// ZITADEL forwards errors from token creation directly to the HTTP response.
// Mark an invalid refresh as an OAuth grant error rather than a server error.
func invalidRefreshGrant() error {
	return oidc.ErrInvalidGrant().WithParent(op.ErrInvalidRefreshToken)
}

func refreshLookupError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return invalidRefreshGrant()
	}
	return err
}

// CreateAccessAndRefreshTokens issues a new opaque refresh token for
// /oauth/token. A refresh marks the old token used and stores the replacement
// in one transaction. Reusing a token revokes its entire family. ZITADEL signs
// the access JWT separately.
func (s *Store) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, current string) (string, string, time.Time, error) {
	clientRequest, ok := request.(interface {
		GetClientID() string
		GetAuthTime() time.Time
	})
	if !ok {
		return "", "", time.Time{}, errors.New("unsupported token request")
	}
	authTime := clientRequest.GetAuthTime()
	absoluteExpiry := authTime.Add(refreshAbsoluteLifetime)
	now := time.Now().UTC()
	if !now.Before(absoluteExpiry) {
		return "", "", time.Time{}, invalidRefreshGrant()
	}
	value, err := randomString()
	if err != nil {
		return "", "", time.Time{}, err
	}
	row := refreshToken{
		TokenHash: hash(value), UserID: request.GetSubject(), ClientID: clientRequest.GetClientID(),
		Scopes: strings.Join(request.GetScopes(), " "), AuthTime: authTime,
	}
	replayed := false
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if current == "" {
			family := refreshFamily{
				ID: uuid.NewString(), UserID: row.UserID, ClientID: row.ClientID, ExpiresAt: absoluteExpiry,
			}
			if err := tx.Create(&family).Error; err != nil {
				return err
			}
			row.FamilyID = family.ID
		} else {
			// Read the family ID, then lock its row. Every operation that changes
			// a chain locks this row before checking the token again.
			var previous refreshToken
			if err := tx.Select("family_id").First(&previous, "token_hash = ?", hash(current)).Error; err != nil {
				return refreshLookupError(err)
			}
			var family refreshFamily
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&family, "id = ?", previous.FamilyID).Error; err != nil {
				return refreshLookupError(err)
			}
			now = time.Now().UTC()
			if family.RevokedAt != nil || !now.Before(family.ExpiresAt) || !now.Before(absoluteExpiry) {
				return invalidRefreshGrant()
			}
			if err := tx.First(&previous, "token_hash = ?", hash(current)).Error; err != nil {
				return refreshLookupError(err)
			}
			if previous.FamilyID != family.ID || previous.UserID != row.UserID || previous.ClientID != row.ClientID ||
				family.UserID != row.UserID || family.ClientID != row.ClientID || !previous.AuthTime.Equal(authTime) {
				return invalidRefreshGrant()
			}
			if previous.UsedAt != nil {
				// Commit the revocation before returning invalid_grant. Returning
				// an error here would roll back the transaction.
				replayed = true
				return tx.Model(&family).Update("revoked_at", now).Error
			}
			if !now.Before(previous.ExpiresAt) {
				return invalidRefreshGrant()
			}
			if err := tx.Model(&previous).Update("used_at", now).Error; err != nil {
				return err
			}
			row.FamilyID = family.ID
			absoluteExpiry = family.ExpiresAt
		}
		row.ExpiresAt = now.Add(refreshTokenLifetime)
		if row.ExpiresAt.After(absoluteExpiry) {
			row.ExpiresAt = absoluteExpiry
		}
		return tx.Create(&row).Error
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	if replayed {
		return "", "", time.Time{}, invalidRefreshGrant()
	}
	return uuid.NewString(), value, now.Add(accessTokenLifetime), nil
}

// TokenRequestByRefreshToken loads an active token or a used-token tombstone.
// The latter must reach CreateAccessAndRefreshTokens so replay revocation occurs
// only after ZITADEL checks the authenticated client's ID against the token.
func (s *Store) TokenRequestByRefreshToken(ctx context.Context, value string) (op.RefreshTokenRequest, error) {
	var row refreshToken
	now := time.Now().UTC()
	if err := s.db.WithContext(ctx).First(&row, "token_hash = ?", hash(value)).Error; err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	var family refreshFamily
	if err := s.db.WithContext(ctx).First(&family, "id = ?", row.FamilyID).Error; err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if family.RevokedAt != nil || !now.Before(family.ExpiresAt) || !now.Before(row.AuthTime.Add(refreshAbsoluteLifetime)) ||
		(row.UsedAt == nil && !now.Before(row.ExpiresAt)) {
		return nil, op.ErrInvalidRefreshToken
	}
	return &row, nil
}

// GetRefreshTokenInfo binds a presented token to its app and returns the stored
// hash for revocation. A used predecessor remains resolvable after its own
// expiry so the current token in its family can still be revoked.
func (s *Store) GetRefreshTokenInfo(ctx context.Context, clientID, value string) (string, string, error) {
	var row refreshToken
	err := s.db.WithContext(ctx).First(&row, "token_hash = ? AND client_id = ?", hash(value), clientID).Error
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return row.UserID, row.TokenHash, nil
}

// RevokeToken ends the refresh family for /revoke, retaining used hashes so
// revocation cannot erase replay evidence. Issued access JWTs stay valid until
// they expire.
func (s *Store) RevokeToken(ctx context.Context, tokenIDOrValue, userID, clientID string) *oidc.Error {
	// The library passes the stored token ID after a successful refresh-token
	// lookup, and the raw value if no lookup succeeded. Access-token IDs have no
	// stored row: those JWTs expire naturally after one hour.
	tokenHash := tokenIDOrValue
	if userID == "" {
		tokenHash = hash(tokenIDOrValue)
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var token refreshToken
		err := tx.First(&token, "token_hash = ? AND client_id = ?", tokenHash, clientID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // RFC 7009 also succeeds for unknown tokens.
		}
		if err != nil {
			return err
		}
		var family refreshFamily
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&family, "id = ?", token.FamilyID).Error; err != nil {
			return err
		}
		if family.ClientID != clientID || family.RevokedAt != nil {
			return nil
		}
		return tx.Model(&family).Update("revoked_at", time.Now().UTC()).Error
	})
	if err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}
