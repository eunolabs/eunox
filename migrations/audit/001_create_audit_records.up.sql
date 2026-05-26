-- Copyright 2026 Eunox Authors
-- SPDX-License-Identifier: BUSL-1.1

-- Audit records table: immutable append-only ledger of signed audit evidence.
CREATE TABLE IF NOT EXISTS audit_records (
    id            TEXT PRIMARY KEY,
    sequence_num  BIGINT NOT NULL,
    replica_id    TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type    TEXT NOT NULL,
    actor_user_id TEXT NOT NULL DEFAULT '',
    actor_tenant_id TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    resource_uid  TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    outcome       TEXT NOT NULL,
    detail        JSONB,
    signature     TEXT NOT NULL,
    algorithm     TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    chain_hash    TEXT NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT '',
    ocsf_event    JSONB,
    metadata      JSONB NOT NULL DEFAULT '{}', -- Reserved for operator-defined key-value metadata (e.g., correlation IDs, deployment labels).
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for chronological queries per tenant.
CREATE INDEX idx_audit_records_tenant_timestamp ON audit_records (tenant_id, timestamp DESC);

-- Index for event type filtering.
CREATE INDEX idx_audit_records_event_type ON audit_records (event_type);

-- Index for chain traversal (per replica, ordered by sequence).
CREATE UNIQUE INDEX idx_audit_records_replica_seq ON audit_records (replica_id, sequence_num);

-- Index for actor lookups.
CREATE INDEX idx_audit_records_actor ON audit_records (actor_user_id);

-- Chain anchors table: cross-chain anchoring checkpoints.
CREATE TABLE IF NOT EXISTS chain_anchors (
    anchor_id     TEXT PRIMARY KEY,
    replica_id    TEXT NOT NULL,
    sequence_num  BIGINT NOT NULL,
    chain_hash    TEXT NOT NULL,
    merkle_root   TEXT NOT NULL,
    backend       TEXT NOT NULL DEFAULT '',
    external_ref  TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for anchor lookups by replica.
CREATE INDEX idx_chain_anchors_replica ON chain_anchors (replica_id, sequence_num DESC);
