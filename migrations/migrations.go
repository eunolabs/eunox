// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package migrations provides the embedded SQL migration files for Eunox
// services. Each exported function returns an [io/fs.FS] rooted at the
// relevant service's migration directory, ready to pass to
// [internal/migrate.Config.Source].
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed minter audit
var fsys embed.FS

// Minter returns an fs.FS rooted at the minter migration directory.
// The files it contains define the api_keys and key_policies schema.
func Minter() fs.FS {
	sub, err := fs.Sub(fsys, "minter")
	if err != nil {
		// fs.Sub only errors when the path is absent in the embedded
		// filesystem — a build-time programmer error, not a runtime condition.
		panic("migrations: sub minter: " + err.Error())
	}
	return sub
}

// Audit returns an fs.FS rooted at the audit migration directory.
// The files it contains define the audit_records and chain_anchors schema.
func Audit() fs.FS {
	sub, err := fs.Sub(fsys, "audit")
	if err != nil {
		panic("migrations: sub audit: " + err.Error())
	}
	return sub
}
