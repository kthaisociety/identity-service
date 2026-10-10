package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"gorm.io/gorm"
)

// migrations holds the schema as goose SQL files (docs/pcr/0005). .gitkeep keeps the directory, and so
// the embed, valid before the first migration exists.
//
//go:embed all:migrations
var migrations embed.FS

// Migrate applies the migrations that haven't run yet. A Postgres advisory lock keeps two instances
// starting at once from migrating together.
func Migrate(ctx context.Context, db *gorm.DB) error {
	fsys, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	return migrate(ctx, db, fsys)
}

// migrate applies the goose SQL files in fsys. Tests call it with fixture migrations, since the real
// ones may not exist yet.
func migrate(ctx context.Context, db *gorm.DB, fsys fs.FS) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys, goose.WithSessionLocker(locker))
	if errors.Is(err, goose.ErrNoMigrations) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("loading migrations: %w", err)
	}
	results, err := p.Up(ctx)
	for _, r := range results {
		log.Printf("migrated %s in %s", r.Source.Path, r.Duration)
	}
	if err != nil {
		return fmt.Errorf("migrating: %w", err)
	}
	return nil
}
