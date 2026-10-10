package database_test

import (
	"context"
	"testing"
	"testing/fstest"

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
