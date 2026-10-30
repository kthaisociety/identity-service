# Identity Service Proposal (IT-5)

**Goal:** Centralize Google sign-in into `identity-service` as an OIDC provider, issue tokens with roles, and unblock companion apps.

---

## 1. Endpoints

### Public Listener (`Port 8010` — Internet-facing)
- `GET  /.well-known/openid-configuration` — OIDC discovery document
- `GET  /.well-known/jwks.json` — Public keys for token verification
- `GET  /authorize` — Validates client ID & PKCE, redirects to Google
- `GET  /auth/callback` — Validates Google token, provisions user, issues one-time code
- `POST /token` — Swaps one-time code + PKCE verifier for signed JWT

### Internal Listener (`Port 8011` — Private Network Only)
*Protected by `X-Service-Secret` header.*
- `GET /v1/users/:id` — Fetch user identity & roles
- `PUT /v1/users/:id/role` — Update roles (`user`, `member`, `admin`)

---

## 2. Database Schema (PostgreSQL)

```sql
-- 1. Users (Identity only; profile data stays in landingpage-backend)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    google_sub VARCHAR(255) NOT NULL UNIQUE,
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

*Note: Registered client IDs and exact redirect URIs are configured via environment variables (ADR 0005).*

---

## 3. Core Go Structs

### Database Models
```go
type User struct {
    ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
    Email     string     `gorm:"uniqueIndex;not null" json:"email"`
    GoogleSub string     `gorm:"uniqueIndex;not null" json:"google_sub"`
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
    Issuer    string   `json:"iss"`   // "http://127.0.0.1:8010"
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
2. **Google Sign-In:** `identity-service` validates PKCE and redirects user to Google.
3. **Callback:** Google returns user to `identity-service:8010/auth/callback`.
   - `identity-service` validates Google ID token (`aud`, `iss`, `email_verified`).
   - Finds or creates `User` in Postgres with default role `user`.
   - Generates single-use 60s authorization code.
   - Redirects browser back to app with code.
4. **Token Exchange:** App backend calls `POST identity-service:8010/token` with code + PKCE verifier.
5. **Session Established:** `identity-service` marks code used and returns signed JWT. App stores JWT in cookie.

---

## 5. Single Sign-On (SSO) & Logout
- **SSO Session:** `identity-service` sets a secure session cookie on its domain upon Google login. When a user navigates to a second KTHAIS app, `identity-service` detects the session and issues a code immediately without prompting for Google credentials again.
- **Logout:** `GET /logout` clears the `identity-service` session cookie and redirects back to the app's post-logout URL.

---

## 6. Changes in `landingpage-backend`
1. **Remove Google OAuth Code:** Delete `goth` and Google client secrets from `landingpage-backend`.
2. **Delegate Login:** Route `/api/v1/auth/login` redirects to `identity-service:8010/authorize`.
3. **Handle Callback:** `/api/v1/auth/callback` calls `identity-service:8010/token` to swap the code for the KTHAIS JWT.
4. **Middleware Verification:** Update `internal/middleware/auth.go` to verify incoming JWTs using public keys cached from `identity-service:8010/.well-known/jwks.json`.
5. **Zero Frontend Changes:** The browser continues receiving the exact same `jwt` cookie with `user_id` and `roles`, keeping `landingpage-frontend` 100% untouched.


