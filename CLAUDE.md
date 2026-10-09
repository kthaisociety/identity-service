# CLAUDE.md

identity-service: the one KTHAIS service for sign-in (OIDC), users and roles, and kthais.com Google
Workspace accounts. The only service that holds Google credentials. Go, Gin, GORM, Postgres. Currently a
skeleton: two listeners, `/health`, the service-secret middleware.

## Commands

- Local Postgres: `docker compose up -d`
- Config: `cp .env.example .env`, then fill in the secrets
- Run: `go run ./cmd/api` (public on `127.0.0.1:8010`, internal on `127.0.0.1:8011` with the example env)
- Test: `go vet ./... && go test -race ./...`
- Acceptance tests (ticket branches only): `go test -tags acceptance ./test/acceptance/...`
- Image: `docker build -t identity-service .`

## Layout

- `cmd/api`: wiring and startup of both listeners
- `internal/config`: env, validated at boot
- `internal/handlers`: one router per listener
- `internal/database`: Postgres connection
- `test/acceptance`: per-ticket acceptance tests

## Rules

- Read `CONTEXT.md` for vocabulary, `docs/adr/` for decisions and `docs/pcr/` for conventions before
  changing a part they cover. Record a new decision as a new ADR or PCR, never by editing an accepted one.
- ADRs 0006–0008 are open: the team decides them. Don't pick an OIDC library, session store or key
  strategy without a new ADR.
- Nothing that manages users or uses Workspace admin rights goes on the public listener (ADR 0003).
- Redirect URIs are matched exactly against config, never by prefix or pattern (ADR 0005).
- landingpage-backend and onboarding-service are references for required behaviour, not code to copy.
- Never log or return tokens, secrets, credentials or users' personal data in errors.
- PR titles and commits are Conventional Commits (`feat:`, `fix:`, `docs:`, …): they drive releases.
