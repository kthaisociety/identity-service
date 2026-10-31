// Package config reads every setting from the environment, once, at boot.
package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
)

// Client is one app allowed to use identity's OIDC endpoints.
type Client struct {
	ID                     string   `json:"id"`
	Secret                 string   `json:"secret"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
}

// The config file is used for providing functionality to extract and validate the environment variables.
type Config struct {
	// Host is the bind address for both listeners. Empty binds all interfaces, which the container
	// needs. Set it to 127.0.0.1 for local dev: a dev machine with a public IP exposes anything bound
	// to 0.0.0.0.
	Host string
	// PublicPort serves the sign-in endpoints apps and browsers use. It is the only port given a
	// public domain (docs/adr/0003).
	PublicPort string
	// InternalPort serves the internal API for other KTHAIS services. It never gets a public domain.
	InternalPort string

	// DatabaseURL is a Postgres connection string, e.g.
	// postgres://identity:identity@127.0.0.1:5437/identity?sslmode=disable.
	DatabaseURL string

	// ServiceSecret is the shared secret callers of the internal API send as X-Service-Secret.
	ServiceSecret       string
	Issuer              string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURI   string
	SigningKeyPEMBase64 string
	CryptoKeyBase64     string
	ClientsJSON         string
	Clients             []Client
}

// Load reads the process environment at startup; main first tries to load a
// local .env without replacing existing variables. Defaults apply only when
// a variable is absent, so local ports can override the image's 8000/8001.
func Load() *Config {
	return &Config{
		Host:                getEnv("HOST", ""),
		PublicPort:          getEnv("PUBLIC_PORT", "8000"),
		InternalPort:        getEnv("INTERNAL_PORT", "8001"),
		DatabaseURL:         getEnv("DATABASE_URL", ""),
		ServiceSecret:       getEnv("IDENTITY_SERVICE_SECRET", ""),
		Issuer:              getEnv("OIDC_ISSUER", ""),
		GoogleClientID:      getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:  getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURI:   getEnv("GOOGLE_REDIRECT_URI", ""),
		SigningKeyPEMBase64: getEnv("OIDC_SIGNING_KEY_PEM_BASE64", ""),
		CryptoKeyBase64:     getEnv("OIDC_CRYPTO_KEY_BASE64", ""),
		ClientsJSON:         getEnv("OIDC_CLIENTS_JSON", ""),
	}
}

// Validate fails if a required setting is missing, naming every missing variable at once.
func (c *Config) Validate() error {
	var missing []string
	for name, value := range map[string]string{
		"DATABASE_URL":                c.DatabaseURL,
		"IDENTITY_SERVICE_SECRET":     c.ServiceSecret,
		"OIDC_ISSUER":                 c.Issuer,
		"GOOGLE_CLIENT_ID":            c.GoogleClientID,
		"GOOGLE_CLIENT_SECRET":        c.GoogleClientSecret,
		"GOOGLE_REDIRECT_URI":         c.GoogleRedirectURI,
		"OIDC_SIGNING_KEY_PEM_BASE64": c.SigningKeyPEMBase64,
		"OIDC_CRYPTO_KEY_BASE64":      c.CryptoKeyBase64,
		"OIDC_CLIENTS_JSON":           c.ClientsJSON,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	if c.PublicPort == c.InternalPort {
		return fmt.Errorf("PUBLIC_PORT and INTERNAL_PORT must differ (both %s)", c.PublicPort)
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Host == "" || (issuer.Scheme != "https" && !(issuer.Scheme == "http" && (issuer.Hostname() == "localhost" || issuer.Hostname() == "127.0.0.1"))) || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.Path != "" {
		return fmt.Errorf("OIDC_ISSUER must be an HTTPS origin (HTTP is allowed only on localhost)")
	}
	redirect, err := url.Parse(c.GoogleRedirectURI)
	if err != nil || redirect.Scheme != issuer.Scheme || redirect.Host != issuer.Host || redirect.Path != "/auth/callback" || redirect.RawQuery != "" || redirect.Fragment != "" {
		return fmt.Errorf("GOOGLE_REDIRECT_URI must be OIDC_ISSUER plus /auth/callback")
	}
	if _, err := base64.StdEncoding.DecodeString(c.SigningKeyPEMBase64); err != nil {
		return fmt.Errorf("OIDC_SIGNING_KEY_PEM_BASE64 is not base64: %w", err)
	}
	cryptoKey, err := base64.StdEncoding.DecodeString(c.CryptoKeyBase64)
	if err != nil || len(cryptoKey) != 32 {
		return fmt.Errorf("OIDC_CRYPTO_KEY_BASE64 must encode 32 bytes")
	}
	if err := json.Unmarshal([]byte(c.ClientsJSON), &c.Clients); err != nil || len(c.Clients) == 0 {
		return fmt.Errorf("OIDC_CLIENTS_JSON must contain at least one client")
	}
	seen := map[string]bool{}
	for _, client := range c.Clients {
		if client.ID == "" || client.Secret == "" || len(client.RedirectURIs) == 0 || seen[client.ID] {
			return fmt.Errorf("each OIDC client needs a unique id, secret and redirect URI")
		}
		seen[client.ID] = true
		for _, raw := range append(slices.Clone(client.RedirectURIs), client.PostLogoutRedirectURIs...) {
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || strings.ContainsAny(u.Host, "*?") || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) || u.Fragment != "" {
				return fmt.Errorf("OIDC client %q has an invalid redirect URI", client.ID)
			}
		}
	}
	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
