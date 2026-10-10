# CLAUDE.md

identity-service: the one KTHAIS service for sign-in (OIDC), users and roles, and kthais.com Google
Workspace accounts. The only service that holds Google credentials. Go, Gin, GORM, Postgres. Currently a
skeleton: two listeners, `/health`, the service-secret middleware.

## Commands

- Local Postgres: `docker compose up -d`
- Config: `cp .env.example .env`, then fill in the secrets
- Run: `go run ./cmd/api` (public on `127.0.0.1:8010`, internal on `127.0.0.1:8011` with the example env)
- Test: `make test` (needs `docker compose up -d`; `go vet ./... && go test -race ./...`)
- Image: `docker build -t identity-service .`

## Layout

- `cmd/api`: wiring and startup of both listeners
- `internal/config`: env, validated at boot
- `internal/handlers`: one router per listener
- `internal/database`: Postgres connection and migrations (`migrations/*.sql`, applied at startup)

## Rules

- Read `CONTEXT.md` for vocabulary, `docs/adr/` for decisions and `docs/pcr/` for conventions before
  changing a part they cover. Record a new decision as a new ADR or PCR, never by editing an accepted one.
- The open questions in the README are the team's to decide. Don't pick an OIDC library, session store
  or key strategy without a new ADR.
- Nothing that manages users or uses Workspace admin rights goes on the public listener (ADR 0003).
- Redirect URIs are matched exactly against config, never by prefix or pattern (ADR 0005).
- landingpage-backend and onboarding-service are references for required behaviour, not code to copy.
- Never log or return tokens, secrets, credentials or users' personal data in errors.
- Schema changes are new SQL files in `internal/database/migrations/`, never `AutoMigrate` (PCR 0005).
- PR titles and commits are Conventional Commits (`feat:`, `fix:`, `docs:`, …): they drive releases.
