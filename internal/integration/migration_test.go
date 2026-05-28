// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package integration

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration_MigrationFilesExist verifies that all required migration files
// are present in the expected location.
func TestMigration_MigrationFilesExist(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		fullPath := filepath.Join(projectRoot(t), dir)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Logf("migration directory %s not found (may use embedded migrations)", dir)
			continue
		}

		entries, err := os.ReadDir(fullPath)
		require.NoError(t, err)

		sqlFiles := 0
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".sql" {
				sqlFiles++
			}
		}
		assert.Greater(t, sqlFiles, 0, "migration directory %s should contain SQL files", dir)
	}
}

// TestMigration_ForwardBackwardPairs verifies that every .up.sql migration has
// a corresponding .down.sql file (and vice versa) enabling reversible migrations.
func TestMigration_ForwardBackwardPairs(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		t.Run(dir, func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), dir)
			entries, err := os.ReadDir(fullPath)
			require.NoError(t, err)

			upFiles := map[string]bool{}
			downFiles := map[string]bool{}

			for _, e := range entries {
				name := e.Name()
				if strings.HasSuffix(name, ".up.sql") {
					base := strings.TrimSuffix(name, ".up.sql")
					upFiles[base] = true
				} else if strings.HasSuffix(name, ".down.sql") {
					base := strings.TrimSuffix(name, ".down.sql")
					downFiles[base] = true
				}
			}

			for base := range upFiles {
				assert.True(t, downFiles[base], "migration %s has .up.sql but missing .down.sql", base)
			}
			for base := range downFiles {
				assert.True(t, upFiles[base], "migration %s has .down.sql but missing .up.sql", base)
			}
			assert.Greater(t, len(upFiles), 0, "directory %s should have at least one migration", dir)
		})
	}
}

// TestMigration_SQLSyntaxBasicValidation performs basic syntax validation on
// migration SQL files (checks for common structural requirements).
func TestMigration_SQLSyntaxBasicValidation(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		t.Run(dir, func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), dir)
			entries, err := os.ReadDir(fullPath)
			require.NoError(t, err)

			for _, e := range entries {
				if filepath.Ext(e.Name()) != ".sql" {
					continue
				}
				t.Run(e.Name(), func(t *testing.T) {
					content, err := os.ReadFile(filepath.Join(fullPath, e.Name()))
					require.NoError(t, err)

					sql := string(content)
					assert.NotEmpty(t, strings.TrimSpace(sql), "migration file should not be empty")

					if strings.HasSuffix(e.Name(), ".up.sql") {
						hasCreate := strings.Contains(strings.ToUpper(sql), "CREATE")
						hasAlter := strings.Contains(strings.ToUpper(sql), "ALTER")
						hasInsert := strings.Contains(strings.ToUpper(sql), "INSERT")
						assert.True(t, hasCreate || hasAlter || hasInsert,
							"up migration should contain CREATE, ALTER, or INSERT statement")
					}

					if strings.HasSuffix(e.Name(), ".down.sql") {
						hasDrop := strings.Contains(strings.ToUpper(sql), "DROP")
						hasAlter := strings.Contains(strings.ToUpper(sql), "ALTER")
						hasDelete := strings.Contains(strings.ToUpper(sql), "DELETE")
						assert.True(t, hasDrop || hasAlter || hasDelete,
							"down migration should contain DROP, ALTER, or DELETE statement")
					}

					assert.True(t, strings.Contains(sql, "SPDX-License-Identifier"),
						"migration file should have license header")
				})
			}
		})
	}
}

// TestMigration_SequentialNumbering verifies migration files follow sequential
// numbering (001, 002, 003, ...) without gaps.
func TestMigration_SequentialNumbering(t *testing.T) {
	migrationDirs := []string{
		"migrations/minter",
		"migrations/audit",
	}

	for _, dir := range migrationDirs {
		t.Run(dir, func(t *testing.T) {
			fullPath := filepath.Join(projectRoot(t), dir)
			entries, err := os.ReadDir(fullPath)
			require.NoError(t, err)

			numbers := map[int]bool{}
			for _, e := range entries {
				name := e.Name()
				if !strings.HasSuffix(name, ".up.sql") {
					continue
				}
				parts := strings.SplitN(name, "_", 2)
				require.NotEmpty(t, parts, "migration filename should have number prefix")
				num, err := strconv.Atoi(parts[0])
				require.NoError(t, err, "migration prefix should be numeric: %s", name)
				numbers[num] = true
			}

			for i := 1; i <= len(numbers); i++ {
				assert.True(t, numbers[i], "migration %03d is missing (gap in sequence)", i)
			}
		})
	}
}
