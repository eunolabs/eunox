-- Copyright 2026 Eunolabs, LLC
-- SPDX-License-Identifier: BUSL-1.1

-- SCIM users table: stores SCIM 2.0 user resources backed by the issuer Postgres DB.
--
-- Key design choices:
--  * id, username, external_id and active are stored as top-level columns for
--    efficient WHERE / INDEX lookups.  The complete SCIMUser struct is kept in
--    the "data" JSONB column so the handler layer can round-trip it without
--    schema migrations for every new SCIM attribute.
--  * created_at is immutable; updated_at is refreshed on every UPSERT.
CREATE TABLE IF NOT EXISTS scim_users (
    id          TEXT        PRIMARY KEY,
    username    TEXT        NOT NULL,
    external_id TEXT        NOT NULL DEFAULT '',
    active      BOOLEAN     NOT NULL DEFAULT TRUE,
    data        JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Case-insensitive username index supports IdP filter userName eq "..."
CREATE INDEX IF NOT EXISTS idx_scim_users_username    ON scim_users (LOWER(username));
CREATE INDEX IF NOT EXISTS idx_scim_users_external_id ON scim_users (LOWER(external_id))
    WHERE external_id != '';

-- SCIM groups table: stores SCIM 2.0 group resources.
--
-- The members array and group display name are both stored in "data" (JSONB).
-- display_name and external_id are duplicated as top-level columns for filtering.
CREATE TABLE IF NOT EXISTS scim_groups (
    id           TEXT        PRIMARY KEY,
    display_name TEXT        NOT NULL,
    external_id  TEXT        NOT NULL DEFAULT '',
    data         JSONB       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_display_name ON scim_groups (LOWER(display_name));
CREATE INDEX IF NOT EXISTS idx_scim_groups_external_id  ON scim_groups (LOWER(external_id))
    WHERE external_id != '';
