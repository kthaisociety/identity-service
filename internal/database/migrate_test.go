package database_test

import (
	"context"
	"os"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/kthaisociety/identity-service/internal/database"
	"github.com/kthaisociety/identity-service/internal/database/databasetest"
)

func TestMigrationsApplyToAnEmptyDatabaseAndRerunAsANoOp(t *testing.T) {
	db := databasetest.Open(t)

	require.NoError(t, database.Migrate(context.Background(), db))
}

// The real migrations folder can be empty, which skips goose entirely, so this runs a fixture.
func TestMigrateRunsSQLOnceAndSkipsItOnRerun(t *testing.T) {
	db := databasetest.OpenEmpty(t)
	fixture := fstest.MapFS{
		"00001_create_widgets.sql": {Data: []byte(`-- +goose Up
CREATE TABLE widgets (id integer PRIMARY KEY);

-- +goose Down
DROP TABLE widgets;
`)},
	}

	require.NoError(t, database.MigrateFS(context.Background(), db, fixture))
	require.True(t, db.Migrator().HasTable("widgets"))

	// A rerun that applied the file again would fail on CREATE TABLE.
	require.NoError(t, database.MigrateFS(context.Background(), db, fixture))
}

func TestRefreshFamilyMigrationBackfillAndRollback(t *testing.T) {
	db := databasetest.OpenEmpty(t)
	ctx := context.Background()
	previous := fstest.MapFS{}
	for _, name := range []string{"00001_identity.sql", "00002_auth_browser.sql"} {
		contents, err := os.ReadFile("migrations/" + name)
		require.NoError(t, err)
		previous[name] = &fstest.MapFile{Data: contents}
	}
	require.NoError(t, database.MigrateFS(ctx, db, previous))

	userID := "00000000-0000-0000-0000-000000000001"
	require.NoError(t, db.Exec("INSERT INTO users (id, email) VALUES (?, ?)", userID, "person@example.com").Error)
	// This interval crosses a daylight-saving change in Europe/Stockholm.
	authTime := time.Date(2026, time.February, 1, 12, 0, 0, 0, time.UTC)
	for _, tokenHash := range []string{"existing-one", "existing-two", "existing-three"} {
		require.NoError(t, db.Exec(`INSERT INTO oidc_refresh_tokens
			(token_hash, user_id, client_id, scopes, auth_time, expires_at)
			VALUES (?, ?, 'app', 'openid offline_access', ?, ?)`,
			tokenHash, userID, authTime, authTime.Add(30*24*time.Hour)).Error)
	}
	require.NoError(t, db.Exec("SET TIME ZONE 'Europe/Stockholm'").Error)
	require.NoError(t, database.Migrate(ctx, db))

	var rows []struct {
		TokenHash string
		FamilyID  string
		ExpiresAt time.Time
	}
	require.NoError(t, db.Raw(`SELECT t.token_hash, t.family_id, f.expires_at
		FROM oidc_refresh_tokens t JOIN oidc_refresh_families f ON f.id = t.family_id
		ORDER BY t.token_hash`).Scan(&rows).Error)
	require.Len(t, rows, 3)
	families := make(map[string]string)
	uniqueIDs := make(map[string]bool)
	for _, row := range rows {
		require.NotEmpty(t, row.FamilyID)
		require.WithinDuration(t, authTime.Add(90*24*time.Hour), row.ExpiresAt, time.Second)
		families[row.TokenHash] = row.FamilyID
		uniqueIDs[row.FamilyID] = true
	}
	require.Len(t, uniqueIDs, 3)

	// Down must not resurrect a consumed or revoked token in the old schema.
	require.NoError(t, db.Exec("UPDATE oidc_refresh_tokens SET used_at = now() WHERE token_hash = 'existing-one'").Error)
	require.NoError(t, db.Exec("UPDATE oidc_refresh_families SET revoked_at = now() WHERE id = ?", families["existing-two"]).Error)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("migrations"))
	require.NoError(t, err)
	_, err = provider.Down(ctx)
	require.NoError(t, err)
	var remaining []string
	require.NoError(t, db.Raw("SELECT token_hash FROM oidc_refresh_tokens").Scan(&remaining).Error)
	require.Equal(t, []string{"existing-three"}, remaining)
}
