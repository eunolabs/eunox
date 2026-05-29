// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package issuer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// pgSCIMRepository implements SCIMRepository backed by PostgreSQL.
//
// H-5/A-4 fix: this implementation replaces the in-memory SCIMStore for
// multi-replica deployments, persisting SCIM 2.0 users and groups across
// restarts and pod replacements.
//
// Schema is defined in migrations/issuer/001_create_scim_tables.up.sql.
// Use NewPostgresSCIMRepository to construct an instance.
type pgSCIMRepository struct {
	db *sql.DB
}

// Ensure pgSCIMRepository satisfies SCIMRepository at compile time.
var _ SCIMRepository = (*pgSCIMRepository)(nil)

// NewPostgresSCIMRepository returns a SCIMRepository backed by db.
// The caller retains ownership of db and is responsible for closing it.
func NewPostgresSCIMRepository(db *sql.DB) SCIMRepository {
	return &pgSCIMRepository{db: db}
}

// ── Users ────────────────────────────────────────────────────────────────────

// CreateUser inserts a new SCIM user row. If a user with the same id already
// exists the call is a no-op (idempotent UPSERT — satisfies IdP retry semantics).
func (r *pgSCIMRepository) CreateUser(ctx context.Context, user *SCIMUser) error {
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("scim postgres: marshal user: %w", err)
	}
	const q = `
		INSERT INTO scim_users (id, username, external_id, active, data)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING`
	if _, err := r.db.ExecContext(ctx, q,
		user.ID, user.UserName, user.ExternalID, user.Active, data,
	); err != nil {
		return fmt.Errorf("scim postgres: create user: %w", err)
	}
	return nil
}

// GetUser fetches a user by id.  Returns (nil, false, nil) when not found.
func (r *pgSCIMRepository) GetUser(ctx context.Context, id string) (*SCIMUser, bool, error) {
	const q = `SELECT data FROM scim_users WHERE id = $1`
	row := r.db.QueryRowContext(ctx, q, id)
	return scanSCIMUser(row)
}

// ListUsers returns all users, optionally filtered by a SCIM filter expression.
// The supported filter syntax matches matchesUserFilter in scim.go.
func (r *pgSCIMRepository) ListUsers(ctx context.Context, filter string) ([]*SCIMUser, error) {
	queryStr, args := buildUserListQuery(filter)
	rows, err := r.db.QueryContext(ctx, queryStr, args...)
	if err != nil {
		return nil, fmt.Errorf("scim postgres: list users: %w", err)
	}
	defer rows.Close()
	return scanSCIMUsers(rows)
}

// UpdateUser replaces an existing user's data.  A no-op when the user is not found.
func (r *pgSCIMRepository) UpdateUser(ctx context.Context, user *SCIMUser) error {
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("scim postgres: marshal user: %w", err)
	}
	const q = `
		UPDATE scim_users
		SET username = $2, external_id = $3, active = $4, data = $5, updated_at = NOW()
		WHERE id = $1`
	if _, err := r.db.ExecContext(ctx, q,
		user.ID, user.UserName, user.ExternalID, user.Active, data,
	); err != nil {
		return fmt.Errorf("scim postgres: update user: %w", err)
	}
	return nil
}

// DeleteUser removes a user by id.  Returns (true, nil) when deleted, (false, nil) when not found.
func (r *pgSCIMRepository) DeleteUser(ctx context.Context, id string) (bool, error) {
	const q = `DELETE FROM scim_users WHERE id = $1`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return false, fmt.Errorf("scim postgres: delete user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("scim postgres: delete user rows affected: %w", err)
	}
	return n > 0, nil
}

// ── Groups ───────────────────────────────────────────────────────────────────

// CreateGroup inserts a new SCIM group row and synchronises the groups field
// on any member users in a single transaction.
func (r *pgSCIMRepository) CreateGroup(ctx context.Context, group *SCIMGroup) error {
	return r.upsertGroupAndSyncMembers(ctx, group, false)
}

// GetGroup fetches a group by id.  Returns (nil, false, nil) when not found.
func (r *pgSCIMRepository) GetGroup(ctx context.Context, id string) (*SCIMGroup, bool, error) {
	const q = `SELECT data FROM scim_groups WHERE id = $1`
	row := r.db.QueryRowContext(ctx, q, id)
	return scanSCIMGroup(row)
}

// ListGroups returns all groups, optionally filtered by a SCIM filter expression.
func (r *pgSCIMRepository) ListGroups(ctx context.Context, filter string) ([]*SCIMGroup, error) {
	queryStr, args := buildGroupListQuery(filter)
	rows, err := r.db.QueryContext(ctx, queryStr, args...)
	if err != nil {
		return nil, fmt.Errorf("scim postgres: list groups: %w", err)
	}
	defer rows.Close()
	return scanSCIMGroups(rows)
}

// UpdateGroup replaces an existing group's data and synchronises member users.
func (r *pgSCIMRepository) UpdateGroup(ctx context.Context, group *SCIMGroup) error {
	return r.upsertGroupAndSyncMembers(ctx, group, true)
}

// DeleteGroup removes a group by id and clears the groups field on member users.
// Returns (true, nil) when deleted, (false, nil) when not found.
func (r *pgSCIMRepository) DeleteGroup(ctx context.Context, id string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("scim postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `DELETE FROM scim_groups WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("scim postgres: delete group: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("scim postgres: delete group rows affected: %w", err)
	}
	if n == 0 {
		return false, nil // not found — no need to sync
	}

	// Remove group reference from all users that carry it in their JSONB data.
	if err := removeGroupFromUsersInTx(ctx, tx, id); err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("scim postgres: commit delete group: %w", err)
	}
	return true, nil
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// upsertGroupAndSyncMembers writes the group row and updates the groups field
// on all affected users inside a single transaction.  When isUpdate is true, the
// group row is replaced (UPDATE); otherwise it is inserted (INSERT … ON CONFLICT DO NOTHING).
func (r *pgSCIMRepository) upsertGroupAndSyncMembers(ctx context.Context, group *SCIMGroup, isUpdate bool) error {
	data, err := json.Marshal(group)
	if err != nil {
		return fmt.Errorf("scim postgres: marshal group: %w", err)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("scim postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if isUpdate {
		const q = `
			UPDATE scim_groups
			SET display_name = $2, external_id = $3, data = $4, updated_at = NOW()
			WHERE id = $1`
		if _, err := tx.ExecContext(ctx, q,
			group.ID, group.DisplayName, group.ExternalID, data,
		); err != nil {
			return fmt.Errorf("scim postgres: update group: %w", err)
		}
	} else {
		const q = `
			INSERT INTO scim_groups (id, display_name, external_id, data)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (id) DO NOTHING`
		if _, err := tx.ExecContext(ctx, q,
			group.ID, group.DisplayName, group.ExternalID, data,
		); err != nil {
			return fmt.Errorf("scim postgres: create group: %w", err)
		}
	}

	// Sync user.groups: first remove stale references, then add current ones.
	if err := removeGroupFromUsersInTx(ctx, tx, group.ID); err != nil {
		return err
	}
	for _, member := range group.Members {
		if err := addGroupRefToUserInTx(ctx, tx, member.Value, SCIMGroupRef{
			Value:   group.ID,
			Display: group.DisplayName,
		}); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("scim postgres: commit group upsert: %w", err)
	}
	return nil
}

// removeGroupFromUsersInTx removes references to groupID from the groups array
// inside every scim_users.data JSONB document, within the supplied transaction.
func removeGroupFromUsersInTx(ctx context.Context, tx *sql.Tx, groupID string) error {
	// Use jsonb_path_query_array to rebuild the groups array without the removed ID.
	const q = `
		UPDATE scim_users
		SET data      = jsonb_set(data, '{groups}',
		                 COALESCE((
		                     SELECT jsonb_agg(elem)
		                     FROM   jsonb_array_elements(COALESCE(data->'groups', '[]'::jsonb)) AS elem
		                     WHERE  elem->>'value' <> $1
		                 ), '[]'::jsonb)),
		    updated_at = NOW()
		WHERE data->'groups' @> jsonb_build_array(jsonb_build_object('value', $1))`
	if _, err := tx.ExecContext(ctx, q, groupID); err != nil {
		return fmt.Errorf("scim postgres: remove group ref from users: %w", err)
	}
	return nil
}

// addGroupRefToUserInTx appends a SCIMGroupRef to a user's groups array in JSONB.
func addGroupRefToUserInTx(ctx context.Context, tx *sql.Tx, userID string, ref SCIMGroupRef) error {
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return fmt.Errorf("scim postgres: marshal group ref: %w", err)
	}
	const q = `
		UPDATE scim_users
		SET data       = jsonb_set(data, '{groups}',
		                  COALESCE(data->'groups', '[]'::jsonb) || $2::jsonb),
		    updated_at = NOW()
		WHERE id = $1`
	if _, err := tx.ExecContext(ctx, q, userID, string(refJSON)); err != nil {
		return fmt.Errorf("scim postgres: add group ref to user: %w", err)
	}
	return nil
}

// ── Query builders ───────────────────────────────────────────────────────────

// buildUserListQuery constructs a SELECT query with an optional WHERE clause
// derived from the SCIM filter string.  The filter syntax supported here matches
// matchesUserFilter in scim.go (attr eq "value").
func buildUserListQuery(filter string) (string, []interface{}) {
	base := `SELECT data FROM scim_users`
	if filter == "" {
		return base + ` ORDER BY created_at, id`, nil
	}
	filter = strings.TrimSpace(filter)
	parts := strings.SplitN(filter, " eq ", 2)
	if len(parts) == 2 {
		attr := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch attr {
		case "username":
			return base + ` WHERE LOWER(username) = LOWER($1) ORDER BY created_at, id`, []interface{}{val}
		case "externalid":
			return base + ` WHERE LOWER(external_id) = LOWER($1) ORDER BY created_at, id`, []interface{}{val}
		case "displayname":
			// displayName on users maps to name.formatted in JSON.
			return base + ` WHERE LOWER(data->>'name'->>'formatted') = LOWER($1) OR ` +
				`LOWER(TRIM(CONCAT(data->'name'->>'givenName', ' ', data->'name'->>'familyName'))) = LOWER($1) ` +
				`ORDER BY created_at, id`, []interface{}{val}
		}
	}
	// Fallback: substring match on username (mirrors in-memory behaviour).
	return base + ` WHERE LOWER(username) LIKE '%' || LOWER($1) || '%' ORDER BY created_at, id`, []interface{}{filter}
}

// buildGroupListQuery constructs a SELECT query with an optional WHERE clause
// derived from the SCIM filter string.
func buildGroupListQuery(filter string) (string, []interface{}) {
	base := `SELECT data FROM scim_groups`
	if filter == "" {
		return base + ` ORDER BY created_at, id`, nil
	}
	filter = strings.TrimSpace(filter)
	parts := strings.SplitN(filter, " eq ", 2)
	if len(parts) == 2 {
		attr := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch attr {
		case "displayname":
			return base + ` WHERE LOWER(display_name) = LOWER($1) ORDER BY created_at, id`, []interface{}{val}
		case "externalid":
			return base + ` WHERE LOWER(external_id) = LOWER($1) ORDER BY created_at, id`, []interface{}{val}
		}
	}
	return base + ` ORDER BY created_at, id`, nil
}

// ── Row scanners ─────────────────────────────────────────────────────────────

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanSCIMUser(row rowScanner) (*SCIMUser, bool, error) {
	var data []byte
	if err := row.Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("scim postgres: scan user: %w", err)
	}
	var u SCIMUser
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, false, fmt.Errorf("scim postgres: unmarshal user: %w", err)
	}
	return &u, true, nil
}

func scanSCIMUsers(rows *sql.Rows) ([]*SCIMUser, error) {
	var users []*SCIMUser
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scim postgres: scan user row: %w", err)
		}
		var u SCIMUser
		if err := json.Unmarshal(data, &u); err != nil {
			return nil, fmt.Errorf("scim postgres: unmarshal user row: %w", err)
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scim postgres: iterate user rows: %w", err)
	}
	return users, nil
}

func scanSCIMGroup(row rowScanner) (*SCIMGroup, bool, error) {
	var data []byte
	if err := row.Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("scim postgres: scan group: %w", err)
	}
	var g SCIMGroup
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, false, fmt.Errorf("scim postgres: unmarshal group: %w", err)
	}
	return &g, true, nil
}

func scanSCIMGroups(rows *sql.Rows) ([]*SCIMGroup, error) {
	var groups []*SCIMGroup
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scim postgres: scan group row: %w", err)
		}
		var g SCIMGroup
		if err := json.Unmarshal(data, &g); err != nil {
			return nil, fmt.Errorf("scim postgres: unmarshal group row: %w", err)
		}
		groups = append(groups, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scim postgres: iterate group rows: %w", err)
	}
	return groups, nil
}
