// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: Apache-2.0

package capability

// Error codes for denial responses.
const (
	ErrCodeAuthorizationFailed = "AUTHORIZATION_FAILED"
	ErrCodeKillSwitch          = "KILL_SWITCH_ACTIVE"
	ErrCodeRevoked             = "TOKEN_REVOKED"
	ErrCodeExpired             = "TOKEN_EXPIRED"
	ErrCodeMissingContext      = "MISSING_CONTEXT"
	ErrCodeInvalidRequest      = "INVALID_REQUEST"
	ErrCodeRateLimited         = "RATE_LIMITED"
	ErrCodeConditionFailed     = "CONDITION_FAILED"
)
