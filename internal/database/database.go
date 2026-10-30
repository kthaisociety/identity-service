// Package database opens the service's Postgres connection.
package database

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open connects and pings, so a wrong DATABASE_URL fails at boot rather than on the first request.
func Open(ctx context.Context, url string) (*gorm.DB, error) {
	// SQL parameters may contain Google subjects or email addresses. Callers
	// handle errors without logging queries or personal data.
	db, err := gorm.Open(postgres.Open(url), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if err := Ping(ctx, db); err != nil {
		return nil, err
	}
	return db, nil
}

func Ping(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}
	return nil
}
