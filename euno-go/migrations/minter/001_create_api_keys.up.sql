-- Copyright 2024-2025 Euno Platform Authors
-- SPDX-License-Identifier: BUSL-1.1

-- API Keys table: stores hashed API keys with metadata.
CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_by   TEXT NOT NULL DEFAULT '',
    metadata     JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);
CREATE INDEX idx_api_keys_created_at ON api_keys (created_at DESC);

-- Policies table: stores key policies.
CREATE TABLE IF NOT EXISTS key_policies (
    policy_id    TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    rules        JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_key_policies_tenant_id ON key_policies (tenant_id);
CREATE UNIQUE INDEX idx_key_policies_tenant_name ON key_policies (tenant_id, name);
