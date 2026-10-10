# 0005. The schema lives in SQL migration files

Status: Accepted

## Convention
- Every schema change is a new [goose](https://github.com/pressly/goose) SQL file in
  `internal/database/migrations/`, numbered in order: `00001_create_x.sql`, with a `-- +goose Up` section
  and, when the change can be undone, `-- +goose Down`.
- The server applies new migrations at startup (`database.Migrate`), before serving requests. No GORM
  `AutoMigrate`: GORM only reads and writes.
- GORM models match their tables. Each model has a test that writes and reads it against a migrated
  database (`databasetest.Open`).
- A merged migration is never edited. Fix it with a new one.

## Why
`AutoMigrate` never drops or renames columns, can't move data, and hides schema changes in struct diffs.
SQL files show the exact change in review, and every environment replays the same history in order.

## How to apply
New file: `go run github.com/pressly/goose/v3/cmd/goose@v3.28.0 -dir internal/database/migrations -s create
<what_it_does> sql`. Run `docker compose up -d`, then `make test`; CI runs the same tests against its own
Postgres.
