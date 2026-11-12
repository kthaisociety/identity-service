-- +goose Up
-- Existing in-progress requests have no browser binding and must be restarted.
ALTER TABLE oidc_auth_requests ADD COLUMN browser_hash text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE oidc_auth_requests DROP COLUMN browser_hash;
