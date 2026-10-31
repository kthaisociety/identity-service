# identity-service

The one KTHAIS service for sign-in, users and roles, and the only one that holds Google credentials.
Every KTHAIS app signs people in through it ([OIDC](https://openid.net/developers/how-connect-works/)),
and other services manage users and kthais.com Google Workspace accounts through its internal API.

**Status: local sign-in prototype.** It serves OIDC authorization code and refresh flows, Google sign-in,
roles in JWTs, JWKS, discovery, and Postgres-backed SSO sessions. The internal `/v1` API, legacy-user
import, Workspace administration and app integration are later rollout steps.

## Start here

1. Read [`CONTEXT.md`](CONTEXT.md) for the vocabulary.
2. Read the decisions in [`docs/adr/`](docs/adr/), including the [OIDC library](docs/adr/0006-zitadel-oidc-provider-library.md),
   [SSO sessions](docs/adr/0007-postgres-sso-sessions.md), and [signing key](docs/adr/0008-single-configured-signing-key.md).
3. Look at the existing services below for behavior that later rollout steps must preserve.

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
| Public | 8000 (`PUBLIC_PORT`) | the internet | OIDC and sign-in; `GET /health` |
| Internal | 8001 (`INTERNAL_PORT`) | the internal network only | `GET /health`; `/v1/…` needs `X-Service-Secret` |

Why two: [ADR 0003](docs/adr/0003-two-listeners.md).

## Running locally

Needs Go 1.27, Docker, a Google OAuth client, and a registered Google callback URL of
`http://127.0.0.1:8010/auth/callback` for local browser sign-in.

```sh
docker compose up -d          # Postgres on 127.0.0.1:5437
cp .env.example .env          # fill in every placeholder and generate both OIDC keys
go run ./cmd/api
curl localhost:8010/health
```

Generate a local RSA key with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` and base64-encode
its PEM bytes for `OIDC_SIGNING_KEY_PEM_BASE64`. Generate 32 random bytes and base64-encode them for
`OIDC_CRYPTO_KEY_BASE64` (`openssl rand -base64 32`). Keep both values stable across restarts. Set
`OIDC_CLIENTS_JSON` to an app's client ID, secret, and exact redirect URI; the example uses a local callback
at port 8012, which needs a running app or callback receiver to see the browser return. The automated
HTTP flow test uses a fake Google provider and callback, so it needs no Google credentials.

Tests: `make test` (`go vet ./...` and `go test -race ./...`; database tests need `docker compose up -d`).
On Windows PowerShell, set `$env:TEST_DATABASE_URL='postgres://identity:identity@127.0.0.1:5437/identity?sslmode=disable'`
and run `go vet ./...` and `go test ./...`. The race check needs CGO and a C compiler, which the
CI Linux runner provides. Tests never call real Google APIs.

The schema is SQL files in `internal/database/migrations/`, applied by the server at startup
([PCR 0005](docs/pcr/0005-sql-migrations.md)).

## Configuration

All from env ([PCR 0001](docs/pcr/0001-config-from-env.md)); see `.env.example`.

| Variable | Secret | |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string |
| `IDENTITY_SERVICE_SECRET` | yes | shared with every caller of the internal API |
| `HOST`, `PUBLIC_PORT`, `INTERNAL_PORT` | no | default all interfaces, `8000`, `8001` |
| `OIDC_ISSUER` | no | public HTTPS origin, or localhost HTTP for development |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | yes | Google OAuth client held only by identity |
| `GOOGLE_REDIRECT_URI` | no | the issuer plus `/auth/callback` |
| `OIDC_SIGNING_KEY_PEM_BASE64`, `OIDC_CRYPTO_KEY_BASE64` | yes | stable signing and encryption keys |
| `OIDC_CLIENTS_JSON` | yes | registered app clients, secrets and exact redirect URIs |

## Sign-in endpoints

Discovery at `/.well-known/openid-configuration` advertises the library's endpoint URLs. The browser
starts at `/authorize`, visits Google through `/login`, and returns to `/auth/callback`. The provider's
`/authorize/callback` sends a one-use code to the app; its backend exchanges that code at `/oauth/token`.
This prototype rejects `prompt` and `max_age` parameters until forced reauthentication and silent-login
behavior are implemented.
The same token endpoint accepts `grant_type=refresh_token`. Apps verify access JWTs against `/keys`,
including issuer, audience and expiry. Access tokens last one hour; refresh tokens rotate and expire after
30 days when the app requests `offline_access` during authorization. The identity browser session lasts
12 hours. `/end_session` ends that browser session; apps must
also clear their own sessions. See [`PROPOSAL.md`](PROPOSAL.md) for the rollout and landingpage cookie plan.

Failed sign-ins and recovered panics log a fixed category, listener, route pattern and status for staging
diagnosis. Request values, personal data, raw errors and panic contents are excluded from these logs.

## Delivery

Like every KTHAIS app ([infrastructure/docs/app-delivery.md](https://github.com/kthaisociety/infrastructure/blob/main/docs/app-delivery.md)):
PRs need a Conventional Commit title; every merge to `main` builds
`ghcr.io/kthaisociety/identity-service:sha-<7>` and deploys it to staging; merging the release PR releases
`X.Y.Z` for production.

## Docs

- [`CONTEXT.md`](CONTEXT.md): vocabulary
- [`docs/adr/`](docs/adr/): decisions about one part of the code
- [`docs/pcr/`](docs/pcr/): conventions for the whole project
