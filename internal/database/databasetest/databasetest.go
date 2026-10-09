// Package databasetest gives tests a fresh, migrated Postgres database (docs/pcr/0005). It needs
// TEST_DATABASE_URL, a Postgres user allowed to create databases: `make test` points it at the
// docker compose database and CI at its own. Without it, tests that use Open are skipped.
package databasetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/kthaisociety/identity-service/internal/database"
)

// Open creates an empty database, applies every migration to it, and drops it when the test ends.
func Open(t *testing.T) *gorm.DB {
	t.Helper()
	adminURL := os.Getenv("TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("TEST_DATABASE_URL is not set: run `docker compose up -d` and `make test`")
	}
	quiet := &gorm.Config{Logger: logger.Discard}

	admin, err := gorm.Open(postgres.Open(adminURL), quiet)
	require.NoError(t, err)
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "test_" + hex.EncodeToString(suffix)
	require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)

	u, err := url.Parse(adminURL)
	require.NoError(t, err)
	u.Path = "/" + name
	db, err := gorm.Open(postgres.Open(u.String()), quiet)
	require.NoError(t, err)

	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = admin.Exec("DROP DATABASE " + name + " WITH (FORCE)").Error
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	require.NoError(t, database.Migrate(context.Background(), db))
	return db
}
