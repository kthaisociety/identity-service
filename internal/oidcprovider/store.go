// Package oidcprovider supplies KTHAIS data and persistent state to the OIDC library.
package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/kthaisociety/identity-service/internal/config"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"gorm.io/gorm"
)

var ErrAccountLinkRequired = errors.New("existing email needs an explicit Google account link")

const (
	// AuthRequestLifetime also sets the browser-bound Google state cookie's lifetime.
	AuthRequestLifetime  = 10 * time.Minute
	codeLifetime         = time.Minute
	accessTokenLifetime  = time.Hour
	refreshTokenLifetime = 30 * 24 * time.Hour
	SessionLifetime      = 12 * time.Hour
)

// signingKey implements op.SigningKey; publicKey implements op.Key.
type signingKey struct {
	id      string
	private *rsa.PrivateKey
}

func (k signingKey) ID() string                                  { return k.id }
func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k signingKey) Algorithm() jose.SignatureAlgorithm          { return jose.RS256 }
func (k signingKey) Use() string                                 { return "sig" }
func (k signingKey) Key() any                                    { return k.private }

type publicKey struct{ signingKey }

func (k publicKey) Key() any { return &k.private.PublicKey }

// Store implements ZITADEL's op.Storage contract across this file, authorization.go,
// and tokens.go. Its other methods support our Google sign-in and browser sessions.
// One Postgres database keeps OIDC state across restarts.
type Store struct {
	db      *gorm.DB
	clients map[string]client
	key     signingKey
}

// NewStore builds our op.Storage implementation from Postgres, registered app
// clients, and a signing key. It also returns the library's encryption key.
func NewStore(db *gorm.DB, cfg *config.Config) (*Store, [32]byte, error) {
	var cryptoKey [32]byte
	decoded, err := base64.StdEncoding.DecodeString(cfg.CryptoKeyBase64)
	if err != nil || len(decoded) != len(cryptoKey) {
		return nil, cryptoKey, errors.New("invalid OIDC encryption key")
	}
	copy(cryptoKey[:], decoded)
	key, err := parseSigningKey(cfg.SigningKeyPEMBase64)
	if err != nil {
		return nil, cryptoKey, err
	}
	clients := make(map[string]client, len(cfg.Clients))
	for _, c := range cfg.Clients {
		clients[c.ID] = client{Client: c, dev: strings.HasPrefix(cfg.Issuer, "http://")}
	}
	return &Store{db: db, clients: clients, key: key}, cryptoKey, nil
}

// parseSigningKey is our configuration helper; the library receives the parsed key.
func parseSigningKey(encoded string) (signingKey, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return signingKey{}, errors.New("invalid signing key encoding")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return signingKey{}, errors.New("invalid signing key PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	} else {
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if key == nil || key.N.BitLen() < 2048 {
		return signingKey{}, errors.New("signing key must be an RSA private key of at least 2048 bits")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return signingKey{}, err
	}
	thumbprint := sha256.Sum256(der)
	return signingKey{id: hex.EncodeToString(thumbprint[:8]), private: key}, nil
}

// randomString and hash are local helpers for opaque values stored by their hashes.
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// GetClientByClientID lets ZITADEL load the app named in /authorize or
// /oauth/token, including its allowed redirects and OIDC capabilities.
func (s *Store) GetClientByClientID(_ context.Context, id string) (op.Client, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, errors.New("unknown client")
	}
	return c, nil
}

// AuthorizeClientIDSecret checks the app's secret during token exchange.
func (s *Store) AuthorizeClientIDSecret(_ context.Context, id, secret string) error {
	c, ok := s.clients[id]
	if !ok || subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		return errors.New("invalid client credentials")
	}
	return nil
}

// SigningKey gives ZITADEL the private key used to sign identity's JWTs.
func (s *Store) SigningKey(context.Context) (op.SigningKey, error) { return s.key, nil }
func (s *Store) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet supplies only the public key advertised at /keys for app verification.
func (s *Store) KeySet(context.Context) ([]op.Key, error) { return []op.Key{publicKey{s.key}}, nil }
func (s *Store) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT client authentication is disabled")
}
func (s *Store) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("JWT profile grant is disabled")
}

// Health lets the provider check that Postgres is reachable.
func (s *Store) Health(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// userInfo reads KTHAIS identity and roles for the userinfo and token-claim
// hooks below. Google does not supply KTHAIS roles.
func (s *Store) userInfo(ctx context.Context, info *oidc.UserInfo, userID string) error {
	var u user
	if err := s.db.WithContext(ctx).First(&u, "id = ?", userID).Error; err != nil {
		return err
	}
	var roles []userRole
	if err := s.db.WithContext(ctx).Find(&roles, "user_id = ?", userID).Error; err != nil {
		return err
	}
	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Role
	}
	info.Subject = u.ID
	info.Email = u.Email
	info.EmailVerified = true
	info.AppendClaims("roles", roleNames)
	return nil
}

// SetUserinfoFromScopes supplies identity claims when ZITADEL creates an ID token.
func (s *Store) SetUserinfoFromScopes(ctx context.Context, info *oidc.UserInfo, userID, _ string, _ []string) error {
	return s.userInfo(ctx, info, userID)
}

// SetUserinfoFromToken supplies the claims returned by /userinfo.
func (s *Store) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, _, subject, _ string) error {
	return s.userInfo(ctx, info, subject)
}

// SetIntrospectionFromToken supplies claims for /oauth/introspect.
func (s *Store) SetIntrospectionFromToken(ctx context.Context, result *oidc.IntrospectionResponse, _, subject, _ string) error {
	info := new(oidc.UserInfo)
	if err := s.userInfo(ctx, info, subject); err != nil {
		return err
	}
	result.SetUserInfo(info)
	return nil
}

// GetPrivateClaimsFromScopes puts the current email and roles into JWT claims
// when ZITADEL issues an access token, including after a refresh.
func (s *Store) GetPrivateClaimsFromScopes(ctx context.Context, userID, _ string, _ []string) (map[string]any, error) {
	info := new(oidc.UserInfo)
	if err := s.userInfo(ctx, info, userID); err != nil {
		return nil, err
	}
	return map[string]any{"email": info.Email, "roles": info.Claims["roles"]}, nil
}

// FindOrCreateGoogleUser is called by our Google callback, not by op.Storage.
// It finds a user by Google's stable subject, updates a changed verified email,
// or creates a user with the default user role. An email match without a
// matching subject requires explicit linking instead of silently joining accounts.
func (s *Store) FindOrCreateGoogleUser(ctx context.Context, subject, email string) (string, error) {
	if subject == "" || email == "" {
		return "", errors.New("missing verified Google identity")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	var id string
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var u user
		err := tx.Where("google_sub = ?", subject).First(&u).Error
		if err == nil {
			if u.Email != email {
				if err := tx.Model(&u).Update("email", email).Error; err != nil {
					return err
				}
			}
			id = u.ID
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var existing user
		err = tx.Where("email = ?", email).First(&existing).Error
		if err == nil {
			return ErrAccountLinkRequired
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		u = user{ID: uuid.NewString(), Email: email, GoogleSub: subject}
		if err := tx.Create(&u).Error; err != nil {
			return err
		}
		if err := tx.Create(&userRole{UserID: u.ID, Role: "user"}).Error; err != nil {
			return err
		}
		id = u.ID
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("saving Google user: %w", err)
	}
	return id, nil
}

var _ op.Storage = (*Store)(nil)
