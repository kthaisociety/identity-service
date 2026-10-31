// Package googleauth handles the upstream Google sign-in. The OIDC provider
// library handles the separate, downstream KTHAIS app protocol.
package googleauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const googleIssuer = "https://accounts.google.com"

type Identity struct {
	Subject string
	Email   string
}

type Client struct {
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	httpClient *http.Client
}

// New discovers Google's OIDC endpoints and prepares the client used by
// /login and /auth/callback. redirectURI is identity's own Google callback.
func New(ctx context.Context, clientID, clientSecret, redirectURI string) (*Client, error) {
	return newClient(ctx, googleIssuer, clientID, clientSecret, redirectURI, http.DefaultClient)
}

// newClient allows tests to supply a fake OIDC issuer and HTTP client.
func newClient(ctx context.Context, issuer, clientID, clientSecret, redirectURI string, httpClient *http.Client) (*Client, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &Client{
		oauth: oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURI,
			Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email"},
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
		httpClient: httpClient,
	}, nil
}

// AuthURL builds the Google sign-in URL with state and identity's configured
// /auth/callback return URL; /login redirects the browser to it.
func (c *Client) AuthURL(state string) string { return c.oauth.AuthCodeURL(state) }

// Exchange trades Google's callback code for an ID token, verifies its
// signature, issuer, audience and expiry, then requires a verified email.
// Google's code and token are separate from the app's later OIDC code and JWTs.
func (c *Client) Exchange(ctx context.Context, code string) (Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	token, err := c.oauth.Exchange(ctx, code)
	if err != nil {
		return Identity{}, err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, errors.New("Google did not return an ID token")
	}
	verified, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, err
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := verified.Claims(&claims); err != nil {
		return Identity{}, err
	}
	if verified.Subject == "" || claims.Email == "" || !claims.EmailVerified {
		return Identity{}, errors.New("Google identity is missing a verified email")
	}
	return Identity{Subject: verified.Subject, Email: claims.Email}, nil
}
