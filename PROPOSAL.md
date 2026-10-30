# Identity Service Proposal (IT-5)

**Goal:** Centralize Google sign-in into `identity-service` as an OIDC provider, issue tokens with roles, and unblock companion apps.

---

## 1. Endpoints

### Public Listener (`Port 8000` in the image; `8010` locally — Internet-facing)
- `GET  /.well-known/openid-configuration` — OIDC discovery document
- `GET  /keys` — Public keys for token verification (JWKS)
- `GET  /authorize` — Validates client ID & PKCE, redirects to Google
- `GET  /auth/callback` — Our Google callback: validates Google's token and completes the user's login
- `GET  /authorize/callback` — ZITADEL provider library's authorization callback: issues the one-time code and redirects to the app
- `POST /oauth/token` — Exchanges a one-time code + PKCE verifier for tokens; also accepts `grant_type=refresh_token`

### Internal Listener (`Port 8001` in the image; `8011` locally — Private Network Only)
*Protected by `X-Service-Secret` header.*
- `GET /v1/users/:id` — Fetch user identity & roles
- `PUT /v1/users/:id/role` — Update roles (`user`, `member`, `admin`)

These are proposed internal endpoints; keep the API thin and add each route when an app needs it.

---

## 2. Database Schema (PostgreSQL)

```sql
-- 1. Users (Identity only; profile data stays in landingpage-backend)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    google_sub VARCHAR(255) UNIQUE, -- nullable until an imported user is safely linked to Google
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. User Roles
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL, -- 'user', 'member', 'admin'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role)
);

-- 3. Short-lived authorization codes (60s TTL)
CREATE TABLE auth_codes (
    code VARCHAR(128) PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(20) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
```

*Note: Registered client IDs and exact redirect URIs are configured via environment variables (ADR 0005). The `user_roles` join table is the agreed roles model. The authorization-code table is a sketch; its final shape must fit the chosen OIDC library's storage interface.*

---

## 3. Core Go Structs

### Database Models
```go
type User struct {
    ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
    Email     string     `gorm:"uniqueIndex;not null" json:"email"`
    GoogleSub *string    `gorm:"uniqueIndex" json:"google_sub"`
    Roles     []UserRole `gorm:"foreignKey:UserID" json:"roles"`
}

type UserRole struct {
    UserID uuid.UUID `gorm:"type:uuid;primaryKey" json:"user_id"`
    Role   string    `gorm:"type:varchar(50);primaryKey" json:"role"`
}
```

### JWT Token Claims (`RS256`)
```go
type Claims struct {
    Issuer    string   `json:"iss"`   // configured issuer URL (HTTPS outside local dev)
    Subject   string   `json:"sub"`   // user UUID
    Audience  string   `json:"aud"`   // client_id, e.g. "landingpage"
    Email     string   `json:"email"`
    Roles     []string `json:"roles"` // ["user", "member"]
    IssuedAt  int64    `json:"iat"`
    ExpiresAt int64    `json:"exp"`   // 1 hour
}
```

---

## 4. Sign-In Flow

1. **User clicks login:** App redirects browser to `identity-service:8010/authorize`.
2. **Google Sign-In:** `identity-service` validates the client, exact redirect URI and PKCE challenge, then redirects the user to Google.
3. **Callback:** Google returns user to `identity-service:8010/auth/callback`.
   - `identity-service` validates the Google ID token's signature, `iss`, `aud`, `exp` and `email_verified`. If any check fails, it does not use the claims.
   - Finds or creates `User` in Postgres with default role `user`.
   - Returns the completed login to the ZITADEL provider library's `/authorize/callback`, which generates a single-use 60s authorization code and redirects the browser back to the app.
4. **Token Exchange:** App backend calls `POST identity-service:8010/oauth/token` with code + PKCE verifier. Identity checks that `client_id` and `redirect_uri` match the stored code, and consumes it only once.
5. **Session Established:** Identity returns signed tokens. The app backend verifies identity's JWT against cached JWKS, including `iss`, `aud` and `exp`; it does not call identity on every request. A role change takes effect at the next refresh.

Access tokens last **1 hour**. The backend uses the refresh token with `POST /oauth/token` and `grant_type=refresh_token` to renew them without a browser redirect. If refresh is too much for the first version, use the agreed fallback of 8-hour tokens without refresh.

---

## 5. Single Sign-On (SSO) & Logout
- **SSO Session:** `identity-service` sets a secure session cookie on its domain upon Google login. When a user navigates to a second KTHAIS app, `identity-service` detects the session and issues a code immediately without prompting for Google credentials again.
- **Logout:** ZITADEL's `GET /end_session` ends the identity session and redirects back to an allowed app post-logout URL; our session cookie must also be cleared.

---

## 6. Changes in `landingpage-backend`
1. **Remove Google OAuth Code:** Delete `goth` and Google client secrets from `landingpage-backend`.
2. **Delegate Login:** Keep `GET /api/v1/auth/google` returning JSON with a `url`, as the current frontend expects. That URL starts identity's `/authorize` flow; the backend keeps the OIDC `state` and PKCE verifier for its callback.
3. **Handle Callback:** `/api/v1/auth/callback` calls `identity-service:8010/oauth/token` to swap the code for the KTHAIS JWT.
4. **Token Verification:** At the exchange, verify identity's JWT using public keys cached from `identity-service:8010/keys`. The existing middleware continues to verify the landingpage's own cookie on subsequent requests.
5. **Keep the Existing Cookie:** After verifying identity's JWT, the backend issues its existing `jwt` cookie with `user_id` and comma-separated `roles`. This translates identity's `sub` and roles array into the current landingpage format. Verify frontend compatibility across login, refresh and logout during the prototype; zero frontend changes is a goal, not a guarantee.
6. **Refresh the Cookie from Identity:** With the preferred refresh-token design, the backend securely retains the identity refresh token. When renewing its local cookie, it calls identity's `/oauth/token` with `grant_type=refresh_token`, verifies the returned JWT, and reissues the cookie with roles from identity rather than from landingpage's user table. Decide refresh-token storage during the prototype. If the 8-hour no-refresh fallback is used, reauthentication replaces this refresh step.

---

## 7. OIDC Library and Signing Key

Use [`github.com/zitadel/oidc/v3/pkg/op`](https://github.com/zitadel/oidc) as the OIDC provider library, as decided in [ADR 0006](docs/adr/0006-zitadel-oidc-provider-library.md). Verify its integration with Gin, Postgres-backed state and this repo's Go version before building the full flow. Google ID-token verification and KTHAIS user/role rules remain our responsibility.

Use the library's default OIDC endpoint paths. In particular, the original proposal's `/token` becomes `/oauth/token` because that is the ZITADEL provider library's default; OAuth does not require either path. Apps obtain the actual paths from `/.well-known/openid-configuration`, so we do not need custom routing just to keep `/token`.

Use one signing key loaded from config and publish its public key through JWKS. Key rotation is outside this first version. Take `iss` from the configured real HTTPS issuer URL, not a hardcoded localhost address.

---

## 8. Rollout and User Import

1. Build a working prototype and test it locally, without calling real Google APIs in tests.
2. Open a draft PR for the core flow and get Sam's green light before merging. Deploy to staging and test there; the README's “Not deployable yet” note is outdated and should be removed in the PR.
3. Bring identity to production.
4. Import existing `landingpage-backend` users and roles, preserving their UUIDs. Identity keeps only ID, email, Google subject and roles; profiles stay in `landingpage-backend`. Existing users have no stored Google subject, so document a safe linking and collision policy before import. No legacy-user import code is needed for the prototype.
5. Point **kthais.com** at identity first. Other apps follow later. Moving Google Workspace account management from `onboarding-service` is separate later work.


