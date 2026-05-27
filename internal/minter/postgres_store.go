// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package minter

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// PostgresKeyStore implements [KeyStore] backed by a PostgreSQL database.
//
// The expected schema is defined in migrations/minter/001_create_api_keys.up.sql.
// Use [NewPostgresKeyStore] to construct an instance.
type PostgresKeyStore struct {
	db *sql.DB
}

// NewPostgresKeyStore returns a PostgresKeyStore that uses the given *sql.DB.
// The caller retains ownership of db and is responsible for closing it.
func NewPostgresKeyStore(db *sql.DB) *PostgresKeyStore {
	return &PostgresKeyStore{db: db}
}

// CreateKey inserts a new API key row.  It returns [ErrKeyExists] if a key with
// the same key_id already exists.
func (s *PostgresKeyStore) CreateKey(ctx context.Context, key *APIKey) error {
	meta, err := json.Marshal(key.Metadata)
	if err != nil {
		return fmt.Errorf("postgres key store: marshal metadata: %w", err)
	}
	const q = `
		INSERT INTO api_keys
			(key_id, secret_hash, tenant_id, description, created_at, expires_at, revoked_at, created_by, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err = s.db.ExecContext(ctx, q,
		key.KeyID,
		key.SecretHash,
		key.TenantID,
		key.Description,
		key.CreatedAt,
		key.ExpiresAt,
		key.RevokedAt,
		key.CreatedBy,
		meta,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrKeyExists
		}
		return fmt.Errorf("postgres key store: create key: %w", err)
	}
	return nil
}

// GetKey retrieves a key by its key_id.  Returns [ErrKeyNotFound] when the key
// does not exist.
func (s *PostgresKeyStore) GetKey(ctx context.Context, keyID string) (*APIKey, error) {
	const q = `
		SELECT key_id, secret_hash, tenant_id, description, created_at, expires_at, revoked_at, created_by, metadata
		FROM api_keys
		WHERE key_id = $1`
	row := s.db.QueryRowContext(ctx, q, keyID)
	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres key store: get key: %w", err)
	}
	return key, nil
}

// CountKeys returns the total number of keys for the given tenant_id (including
// revoked and expired keys).
func (s *PostgresKeyStore) CountKeys(ctx context.Context, tenantID string) (int, error) {
	const q = `SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1`
	var n int
	if err := s.db.QueryRowContext(ctx, q, tenantID).Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres key store: count keys: %w", err)
	}
	return n, nil
}

// ListKeys returns a page of keys for the given tenant ordered by created_at
// ascending (oldest first) then key_id for tie-breaking — matching the
// in-memory store behavior and the established pagination contract.  Both limit
// and offset are applied server-side.  limit ≤ 0 disables the limit (returns
// all remaining rows from offset).
func (s *PostgresKeyStore) ListKeys(ctx context.Context, tenantID string, limit, offset int) ([]*APIKey, error) {
	const baseQ = `
		SELECT key_id, secret_hash, tenant_id, description, created_at, expires_at, revoked_at, created_by, metadata
		FROM api_keys
		WHERE tenant_id = $1
		ORDER BY created_at ASC, key_id ASC
		OFFSET $2`

	var (
		rows *sql.Rows
		err  error
	)
	if limit > 0 {
		rows, err = s.db.QueryContext(ctx, baseQ+" LIMIT $3", tenantID, offset, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, baseQ, tenantID, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("postgres key store: list keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []*APIKey
	for rows.Next() {
		key, err := scanAPIKeyRow(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres key store: scan key: %w", err)
		}
		result = append(result, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres key store: list keys rows: %w", err)
	}
	return result, nil
}

// RevokeKey marks a key as revoked and returns a snapshot of the key with
// RevokedAt set.  The update is atomic: the SELECT and UPDATE are executed in a
// single serialisable transaction to prevent the TOCTOU race described in CR-5.
//
// Returns [ErrKeyNotFound] if the key does not exist, [ErrKeyRevoked] if the
// key is already revoked.
func (s *PostgresKeyStore) RevokeKey(ctx context.Context, keyID string, revokedAt time.Time) (*APIKey, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("postgres key store: begin revoke tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const selectQ = `
		SELECT key_id, secret_hash, tenant_id, description, created_at, expires_at, revoked_at, created_by, metadata
		FROM api_keys
		WHERE key_id = $1
		FOR UPDATE`
	row := tx.QueryRowContext(ctx, selectQ, keyID)
	key, err := scanAPIKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres key store: revoke key select: %w", err)
	}
	if key.RevokedAt != nil {
		return nil, ErrKeyRevoked
	}

	const updateQ = `UPDATE api_keys SET revoked_at = $1 WHERE key_id = $2`
	if _, err = tx.ExecContext(ctx, updateQ, revokedAt, keyID); err != nil {
		return nil, fmt.Errorf("postgres key store: revoke key update: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("postgres key store: revoke key commit: %w", err)
	}
	key.RevokedAt = &revokedAt
	return key, nil
}

// CreatePolicy inserts a new policy row.  Returns [ErrPolicyExists] if a policy
// with the same (tenant_id, name) pair already exists.
func (s *PostgresKeyStore) CreatePolicy(ctx context.Context, p *Policy) error {
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return fmt.Errorf("postgres key store: marshal policy rules: %w", err)
	}
	const q = `
		INSERT INTO key_policies
			(policy_id, tenant_id, name, description, rules, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err = s.db.ExecContext(ctx, q,
		p.PolicyID,
		p.TenantID,
		p.Name,
		p.Description,
		rules,
		p.CreatedAt,
		p.UpdatedAt,
		p.CreatedBy,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrPolicyExists
		}
		return fmt.Errorf("postgres key store: create policy: %w", err)
	}
	return nil
}

// GetPolicy retrieves a policy by its policy_id.  Returns [ErrPolicyNotFound]
// when the policy does not exist.
func (s *PostgresKeyStore) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	const q = `
		SELECT policy_id, tenant_id, name, description, rules, created_at, updated_at, created_by
		FROM key_policies
		WHERE policy_id = $1`
	row := s.db.QueryRowContext(ctx, q, policyID)
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres key store: get policy: %w", err)
	}
	return p, nil
}

// GetPolicyByName retrieves a policy by (tenant_id, name).  Returns
// [ErrPolicyNotFound] when no match exists.
func (s *PostgresKeyStore) GetPolicyByName(ctx context.Context, tenantID, name string) (*Policy, error) {
	const q = `
		SELECT policy_id, tenant_id, name, description, rules, created_at, updated_at, created_by
		FROM key_policies
		WHERE tenant_id = $1 AND name = $2`
	row := s.db.QueryRowContext(ctx, q, tenantID, name)
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres key store: get policy by name: %w", err)
	}
	return p, nil
}

// ListPolicies returns all policies for a tenant ordered by created_at ASC.
func (s *PostgresKeyStore) ListPolicies(ctx context.Context, tenantID string) ([]*Policy, error) {
	const q = `
		SELECT policy_id, tenant_id, name, description, rules, created_at, updated_at, created_by
		FROM key_policies
		WHERE tenant_id = $1
		ORDER BY created_at ASC, policy_id ASC`
	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("postgres key store: list policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []*Policy
	for rows.Next() {
		p, err := scanPolicyRow(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres key store: scan policy: %w", err)
		}
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres key store: list policies rows: %w", err)
	}
	return result, nil
}

// UpdatePolicy replaces all mutable fields on an existing policy.  Returns
// [ErrPolicyNotFound] if no row with the given policy_id exists.
func (s *PostgresKeyStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	rules, err := json.Marshal(p.Rules)
	if err != nil {
		return fmt.Errorf("postgres key store: marshal updated policy rules: %w", err)
	}
	const q = `
		UPDATE key_policies
		SET name = $1, description = $2, rules = $3, updated_at = $4
		WHERE policy_id = $5`
	res, err := s.db.ExecContext(ctx, q,
		p.Name,
		p.Description,
		rules,
		p.UpdatedAt,
		p.PolicyID,
	)
	if err != nil {
		return fmt.Errorf("postgres key store: update policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres key store: update policy rows affected: %w", err)
	}
	if n == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// DeletePolicy removes a policy row.  Returns [ErrPolicyNotFound] if the policy
// does not exist.
func (s *PostgresKeyStore) DeletePolicy(ctx context.Context, policyID string) error {
	const q = `DELETE FROM key_policies WHERE policy_id = $1`
	res, err := s.db.ExecContext(ctx, q, policyID)
	if err != nil {
		return fmt.Errorf("postgres key store: delete policy: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres key store: delete policy rows affected: %w", err)
	}
	if n == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// ---- scan helpers ----

// rowScanner is satisfied by *sql.Row and each row from *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAPIKey(r rowScanner) (*APIKey, error) {
	var (
		key      APIKey
		metaJSON []byte
	)
	if err := r.Scan(
		&key.KeyID,
		&key.SecretHash,
		&key.TenantID,
		&key.Description,
		&key.CreatedAt,
		&key.ExpiresAt,
		&key.RevokedAt,
		&key.CreatedBy,
		&metaJSON,
	); err != nil {
		return nil, err
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &key.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &key, nil
}

func scanAPIKeyRow(rows *sql.Rows) (*APIKey, error) {
	var (
		key      APIKey
		metaJSON []byte
	)
	if err := rows.Scan(
		&key.KeyID,
		&key.SecretHash,
		&key.TenantID,
		&key.Description,
		&key.CreatedAt,
		&key.ExpiresAt,
		&key.RevokedAt,
		&key.CreatedBy,
		&metaJSON,
	); err != nil {
		return nil, err
	}
	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &key.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return &key, nil
}

func scanPolicy(r rowScanner) (*Policy, error) {
	var (
		p         Policy
		rulesJSON []byte
	)
	if err := r.Scan(
		&p.PolicyID,
		&p.TenantID,
		&p.Name,
		&p.Description,
		&rulesJSON,
		&p.CreatedAt,
		&p.UpdatedAt,
		&p.CreatedBy,
	); err != nil {
		return nil, err
	}
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &p.Rules); err != nil {
			return nil, fmt.Errorf("unmarshal policy rules: %w", err)
		}
	}
	return &p, nil
}

func scanPolicyRow(rows *sql.Rows) (*Policy, error) {
	var (
		p         Policy
		rulesJSON []byte
	)
	if err := rows.Scan(
		&p.PolicyID,
		&p.TenantID,
		&p.Name,
		&p.Description,
		&rulesJSON,
		&p.CreatedAt,
		&p.UpdatedAt,
		&p.CreatedBy,
	); err != nil {
		return nil, err
	}
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &p.Rules); err != nil {
			return nil, fmt.Errorf("unmarshal policy rules: %w", err)
		}
	}
	return &p, nil
}

// isUniqueViolation detects PostgreSQL unique-constraint violations (SQLSTATE 23505)
// using a typed assertion against *pgconn.PgError.  The previous string-
// match on err.Error() could produce false positives when a row value happened
// to contain the digit sequence "23505".
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
