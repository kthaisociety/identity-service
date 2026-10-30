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

func (s *Store) CreateAuthRequest(ctx context.Context, incoming *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	a := &authRequest{
		ID: uuid.NewString(), ClientID: incoming.ClientID, RedirectURI: incoming.RedirectURI,
		State: incoming.State, Nonce: incoming.Nonce, Scopes: strings.Join(incoming.Scopes, " "),
		ResponseType: string(incoming.ResponseType), ResponseMode: string(incoming.ResponseMode),
		CodeChallenge: incoming.CodeChallenge, CodeChallengeMethod: string(incoming.CodeChallengeMethod),
		UserID: userID, CreatedAt: time.Now().UTC(),
	}
	if err := s.db.WithContext(ctx).Create(a).Error; err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	var a authRequest
	err := s.db.WithContext(ctx).First(&a, "id = ? AND created_at > ?", id, time.Now().UTC().Add(-AuthRequestLifetime)).Error
	return &a, err
}

func (s *Store) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	// Consuming on lookup makes concurrent exchanges unable to redeem the same code.
	var a authRequest
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var candidate authRequest
		if err := tx.Where("code_hash = ? AND code_used = false AND code_expires_at > ?", hash(code), time.Now().UTC()).First(&candidate).Error; err != nil {
			return err
		}
		result := tx.Model(&authRequest{}).Where("id = ? AND code_used = false", candidate.ID).Update("code_used", true)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("code already used")
		}
		a = candidate
		return nil
	})
	return &a, err
}

func (s *Store) SaveAuthCode(ctx context.Context, id, code string) error {
	expires := time.Now().UTC().Add(codeLifetime)
	result := s.db.WithContext(ctx).Model(&authRequest{}).
		Where("id = ? AND done = true AND created_at > ? AND code_hash IS NULL", id, time.Now().UTC().Add(-AuthRequestLifetime)).
		Updates(map[string]any{"code_hash": hash(code), "code_expires_at": expires})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("authorization request is not ready")
	}
	return nil
}

func (s *Store) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&authRequest{}, "id = ?", id).Error
}

func (s *Store) BeginGoogle(ctx context.Context, requestID string) (string, error) {
	state, err := randomString()
	if err != nil {
		return "", err
	}
	stateHash := hash(state)
	result := s.db.WithContext(ctx).Model(&authRequest{}).
		Where("id = ? AND done = false AND created_at > ?", requestID, time.Now().UTC().Add(-AuthRequestLifetime)).
		Update("google_state_hash", stateHash)
	if result.Error != nil {
		return "", result.Error
	}
	if result.RowsAffected != 1 {
		return "", errors.New("authorization request expired")
	}
	return state, nil
}

func (s *Store) CompleteGoogle(ctx context.Context, state, userID string) (string, time.Time, error) {
	var requestID string
	var authTime time.Time
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var a authRequest
		if err := tx.Where("google_state_hash = ? AND created_at > ? AND done = false", hash(state), time.Now().UTC().Add(-AuthRequestLifetime)).First(&a).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		result := tx.Model(&authRequest{}).Where("id = ? AND google_state_hash = ? AND done = false", a.ID, hash(state)).
			Updates(map[string]any{"google_state_hash": nil, "user_id": userID, "auth_time": now, "done": true})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("Google state already used")
		}
		requestID = a.ID
		authTime = now
		return nil
	})
	return requestID, authTime, err
}

func (s *Store) RequestIDForGoogleState(ctx context.Context, state string) (string, error) {
	var a authRequest
	err := s.db.WithContext(ctx).First(&a, "google_state_hash = ? AND created_at > ? AND done = false", hash(state), time.Now().UTC().Add(-AuthRequestLifetime)).Error
	return a.ID, err
}

func (s *Store) CompleteSessionLogin(ctx context.Context, requestID, userID string, authTime time.Time) error {
	now := time.Now().UTC()
	result := s.db.WithContext(ctx).Model(&authRequest{}).
		Where("id = ? AND done = false AND created_at > ?", requestID, now.Add(-AuthRequestLifetime)).
		Updates(map[string]any{"user_id": userID, "auth_time": authTime, "done": true})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("authorization request expired")
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, authTime time.Time) (string, error) {
	value, err := randomString()
	if err != nil {
		return "", err
	}
	err = s.db.WithContext(ctx).Create(&session{IDHash: hash(value), UserID: userID, AuthTime: authTime, ExpiresAt: time.Now().UTC().Add(SessionLifetime)}).Error
	return value, err
}

func (s *Store) SessionUser(ctx context.Context, value string) (string, time.Time, error) {
	if value == "" {
		return "", time.Time{}, gorm.ErrRecordNotFound
	}
	var row session
	err := s.db.WithContext(ctx).First(&row, "id_hash = ? AND expires_at > ?", hash(value), time.Now().UTC()).Error
	return row.UserID, row.AuthTime, err
}

func (s *Store) EndSession(ctx context.Context, value string) error {
	if value == "" {
		return nil
	}
	return s.db.WithContext(ctx).Delete(&session{}, "id_hash = ?", hash(value)).Error
}

func (s *Store) TerminateSession(ctx context.Context, userID, clientID string) error {
	// Logout without an ID token hint has no subject. The HTTP handler still
	// removes the current browser session using its cookie.
	if userID == "" {
		return nil
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&session{}, "user_id = ?", userID).Error; err != nil {
			return err
		}
		return tx.Delete(&refreshToken{}, "user_id = ? AND client_id = ?", userID, clientID).Error
	})
}
