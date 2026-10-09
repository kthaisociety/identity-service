// Package config reads every setting from the environment, once, at boot.
package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

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
	// postgres://identity:identity@127.0.0.1:5435/identity?sslmode=disable.
	DatabaseURL string

	// ServiceSecret is the shared secret callers of the internal API send as X-Service-Secret.
	ServiceSecret string
}

func Load() *Config {
	return &Config{
		Host:          getEnv("HOST", ""),
		PublicPort:    getEnv("PUBLIC_PORT", "8000"),
		InternalPort:  getEnv("INTERNAL_PORT", "8001"),
		DatabaseURL:   getEnv("DATABASE_URL", ""),
		ServiceSecret: getEnv("IDENTITY_SERVICE_SECRET", ""),
	}
}

// Validate fails if a required setting is missing, naming every missing variable at once.
func (c *Config) Validate() error {
	var missing []string
	for name, value := range map[string]string{
		"DATABASE_URL":            c.DatabaseURL,
		"IDENTITY_SERVICE_SECRET": c.ServiceSecret,
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
	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
