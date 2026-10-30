-- +goose Up
CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE,
    google_sub text UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('user', 'member', 'admin')),
    PRIMARY KEY (user_id, role)
);

CREATE TABLE oidc_auth_requests (
    id text PRIMARY KEY,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    state text NOT NULL,
    nonce text NOT NULL,
    scopes text NOT NULL,
    response_type text NOT NULL,
    response_mode text NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method text NOT NULL,
    user_id text NOT NULL DEFAULT '',
    auth_time timestamptz,
    done boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    code_hash text UNIQUE,
    code_expires_at timestamptz,
    code_used boolean NOT NULL DEFAULT false,
    google_state_hash text UNIQUE
);

CREATE TABLE oidc_refresh_tokens (
    token_hash text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    scopes text NOT NULL,
    auth_time timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE oidc_sessions (
    id_hash text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE oidc_sessions;
DROP TABLE oidc_refresh_tokens;
DROP TABLE oidc_auth_requests;
DROP TABLE user_roles;
DROP TABLE users;
