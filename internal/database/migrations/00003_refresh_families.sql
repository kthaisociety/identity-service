-- +goose Up
-- A family groups every rotation of one original refresh token. Keeping used
-- token hashes lets identity detect replay until the original sign-in expires.
CREATE TABLE oidc_refresh_families (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX oidc_refresh_families_user_client_idx ON oidc_refresh_families (user_id, client_id);

ALTER TABLE oidc_refresh_tokens ADD COLUMN family_id uuid;
ALTER TABLE oidc_refresh_tokens ADD COLUMN used_at timestamptz;

-- Previously issued tokens each start their own family. The old rotation code
-- deleted predecessors, so there is no earlier chain to reconstruct.
UPDATE oidc_refresh_tokens SET family_id = gen_random_uuid();
-- Use fixed hours to match Go's 90 * 24-hour limit across daylight-saving changes.
INSERT INTO oidc_refresh_families (id, user_id, client_id, expires_at)
SELECT family_id, user_id, client_id, auth_time + interval '2160 hours'
FROM oidc_refresh_tokens;

ALTER TABLE oidc_refresh_tokens ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE oidc_refresh_tokens
    ADD CONSTRAINT oidc_refresh_tokens_family_id_fkey
    FOREIGN KEY (family_id) REFERENCES oidc_refresh_families(id) ON DELETE CASCADE;
CREATE INDEX oidc_refresh_tokens_family_id_idx ON oidc_refresh_tokens (family_id);

-- +goose Down
-- The old schema cannot represent used or revoked tokens. Remove them so a
-- rollback cannot make an already-consumed refresh token usable again.
DELETE FROM oidc_refresh_tokens
WHERE used_at IS NOT NULL OR family_id IN (
    SELECT id FROM oidc_refresh_families WHERE revoked_at IS NOT NULL
);
DROP INDEX oidc_refresh_tokens_family_id_idx;
ALTER TABLE oidc_refresh_tokens DROP CONSTRAINT oidc_refresh_tokens_family_id_fkey;
ALTER TABLE oidc_refresh_tokens DROP COLUMN used_at;
ALTER TABLE oidc_refresh_tokens DROP COLUMN family_id;
DROP TABLE oidc_refresh_families;
