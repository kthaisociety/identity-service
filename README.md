# identity-service

The one KTHAIS service for sign-in, users and roles, and the only one that holds Google credentials.
Every KTHAIS app signs people in through it ([OIDC](https://openid.net/developers/how-connect-works/)),
and other services manage users and kthais.com Google Workspace accounts through its internal API.

**Status: skeleton.** It starts, connects to Postgres and answers `/health`. Everything else is to build.

## Start here

1. Read [`CONTEXT.md`](CONTEXT.md) for the vocabulary.
2. Read the decisions in [`docs/adr/`](docs/adr/). 0001–0005 are decided. 0006–0008 are open, and deciding
   them is part of the work.
3. Look at what exists today (below), then design this service from a clean slate.

### What exists today

The current code shows **what the service has to do**. It is not a template: don't copy its structure or
patterns. Some of it is known to be wrong (see the first bullet).

- **[landingpage-backend](https://github.com/kthaisociety/landingpage-backend)**: sign-in, users and roles
  for kthais.com.
  - `internal/handlers/auth_handler.go`: Google sign-in, session tokens, refresh, logout, and a token
    exchange for the MCP service.
  - `internal/utils/jwt.go`: token handling. `ParseAndVerifyGoogle` never checks `aud` or `email_verified`,
    and `GoogleCallback` uses the claims even when the token is invalid. Don't repeat this.
  - `internal/models/user.go`: users and roles (`user`, `member`, `admin`).
  - Sign-in isn't limited to kthais.com accounts: applicants sign in with their own Google accounts.
- **[onboarding-service](https://github.com/kthaisociety/onboarding-service)**: kthais.com Google Workspace
  accounts.
  - `internal/googleworkspace`: the Workspace admin client.
  - `internal/provisioning`: creating accounts and group memberships.
  - `internal/offboarding`: deactivating and deleting accounts.

Only the Workspace account part moves here ([ADR 0001](docs/adr/0001-scope-users-roles-workspace.md)).
Emails, the onboarding pages and Mattermost stay in onboarding-service.

## Listeners

| Listener | Port in the image | Reachable from | |
|---|---|---|---|
| Public | 8000 (`PUBLIC_PORT`) | the internet | sign-in. `GET /health` |
| Internal | 8001 (`INTERNAL_PORT`) | the internal network only | `GET /health`; `/v1/…` needs `X-Service-Secret` |

Why two: [ADR 0003](docs/adr/0003-two-listeners.md).

## Running locally

Needs Go 1.27 and Docker.

```sh
docker compose up -d          # Postgres on 127.0.0.1:5435
cp .env.example .env          # then fill in IDENTITY_SERVICE_SECRET
go run ./cmd/api
curl localhost:8010/health
```

Tests: `go vet ./... && go test -race ./...`. They never call real Google APIs.

## Configuration

All from env ([PCR 0002](docs/pcr/0002-config-from-env.md)); see `.env.example`.

| Variable | Secret | |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string |
| `IDENTITY_SERVICE_SECRET` | yes | shared with every caller of the internal API |
| `HOST`, `PUBLIC_PORT`, `INTERNAL_PORT` | no | default all interfaces, `8000`, `8001` |

## Delivery

Like every KTHAIS app ([infrastructure/docs/app-delivery.md](https://github.com/kthaisociety/infrastructure/blob/main/docs/app-delivery.md)):
PRs need a Conventional Commit title; every merge to `main` builds
`ghcr.io/kthaisociety/identity-service:sha-<7>` and deploys it to staging; merging the release PR releases
`X.Y.Z` for production.

**Not deployable yet.** The pipeline doesn't support databases or public domains yet, so the staging
deploy fails until it does. Develop and test locally; CI still runs on every PR.

## Docs

- [`CONTEXT.md`](CONTEXT.md): vocabulary
- [`docs/adr/`](docs/adr/): decisions about one part of the code
- [`docs/pcr/`](docs/pcr/): conventions for the whole project
