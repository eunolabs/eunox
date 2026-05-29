-- Copyright 2026 Eunolabs, LLC
-- SPDX-License-Identifier: BUSL-1.1

DROP INDEX IF EXISTS idx_chain_anchors_replica;
DROP TABLE IF EXISTS chain_anchors;

DROP INDEX IF EXISTS idx_audit_records_actor;
DROP INDEX IF EXISTS idx_audit_records_replica_seq;
DROP INDEX IF EXISTS idx_audit_records_event_type;
DROP INDEX IF EXISTS idx_audit_records_tenant_timestamp;
DROP TABLE IF EXISTS audit_records;
