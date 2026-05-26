// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

// Package config provides configuration models, loading, and validation helpers for Euno services.
package config

// DefaultMaxRequestBodySize is the default maximum request body size (1 MB).
// Services should use their configured MaxRequestBodySize field when available,
// falling back to this constant for backward compatibility.
const DefaultMaxRequestBodySize = 1 << 20 // 1 MB
