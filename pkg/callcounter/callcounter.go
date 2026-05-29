// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

// Package callcounter provides a sliding-window call counter for rate limiting.
package callcounter

import "context"

// Store tracks call counts within sliding time windows.
type Store interface {
	// IncrementAndGet atomically increments the counter for the given key
	// and returns the new count. The counter expires after windowSec seconds.
	IncrementAndGet(ctx context.Context, key string, windowSec int) (int64, error)
}
