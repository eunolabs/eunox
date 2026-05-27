// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net/url"
	"strings"
)

// RedisHAError represents a Redis high-availability validation failure.
type RedisHAError struct {
	EnvVar string
	URL    string
	Reason string
}

func (e *RedisHAError) Error() string {
	return fmt.Sprintf("%s: %s", e.EnvVar, e.Reason)
}

// CheckRedisHA validates that all configured Redis URLs are HA-compatible
// (Sentinel or Cluster) when running in production. Returns nil if all URLs
// pass validation or if the environment is not production.
func CheckRedisHA(env Environment, urls map[string]string) []RedisHAError {
	if env != EnvProduction {
		return nil
	}

	var errs []RedisHAError
	for envVar, rawURL := range urls {
		if rawURL == "" {
			continue
		}
		if err := validateRedisURL(envVar, rawURL); err != nil {
			errs = append(errs, *err)
		}
	}
	return errs
}

// validateRedisURL checks whether a Redis URL indicates a HA setup.
// HA indicators:
//   - redis-sentinel:// or redis+sentinel:// scheme
//   - rediss+sentinel:// scheme (Sentinel over TLS)
//   - redis-cluster:// scheme
//   - Multiple hosts (comma-separated) in the URL
//   - Query parameter ?sentinel_master_name= present
func validateRedisURL(envVar, rawURL string) *RedisHAError {
	trimmed := strings.TrimSpace(rawURL)

	// Sentinel schemes are always HA.
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "redis-sentinel://") ||
		strings.HasPrefix(lower, "redis+sentinel://") ||
		strings.HasPrefix(lower, "rediss+sentinel://") ||
		strings.HasPrefix(lower, "redis-cluster://") {
		return nil
	}

	// Check for comma-separated hosts (common in cluster/sentinel configs).
	if containsMultipleHosts(trimmed) {
		return nil
	}

	// Check for sentinel query parameters.
	if hasSentinelParams(trimmed) {
		return nil
	}

	// Single-node Redis in production is not allowed.
	return &RedisHAError{
		EnvVar: envVar,
		URL:    redactURL(trimmed),
		Reason: "single-node Redis is not allowed in production; use Redis Sentinel (redis-sentinel://) or Redis Cluster (redis-cluster://) for high availability",
	}
}

// containsMultipleHosts checks if the URL has multiple comma-separated hosts.
func containsMultipleHosts(rawURL string) bool {
	// Strip scheme for parsing.
	after := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		after = rawURL[idx+3:]
	}
	// Strip auth.
	if idx := strings.LastIndex(after, "@"); idx >= 0 {
		after = after[idx+1:]
	}
	// Strip path and query.
	if idx := strings.IndexAny(after, "/?"); idx >= 0 {
		after = after[:idx]
	}
	// Multiple hosts are comma-separated.
	return strings.Contains(after, ",")
}

// hasSentinelParams checks for sentinel-related query parameters.
func hasSentinelParams(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	q := u.Query()
	return q.Get("sentinel_master_name") != "" || q.Get("sentinelMasterName") != ""
}

// redactURL redacts credentials from a URL for error reporting.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// If we can't parse, just return scheme + host hint.
		return "<unparseable>"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.Redacted()
}

// CheckGatewayRedisHA is a convenience function that validates all gateway
// Redis URLs. It returns a fatal error if any single-node URL is detected
// in production.
func CheckGatewayRedisHA(cfg *GatewayConfig) error {
	urls := map[string]string{
		"REDIS_URL":              cfg.RedisURL,
		"REVOCATION_REDIS_URL":   cfg.RevocationRedisURL,
		"KILL_SWITCH_REDIS_URL":  cfg.KillSwitchRedisURL,
		"CALL_COUNTER_REDIS_URL": cfg.CallCounterRedisURL,
		"DPOP_REDIS_URL":         cfg.DPoPRedisURL,
		"RATE_LIMITER_REDIS_URL": cfg.RateLimiterRedisURL,
	}

	errs := CheckRedisHA(cfg.NodeEnv, urls)
	if len(errs) == 0 {
		return nil
	}

	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Errorf("production Redis HA validation failed:\n  %s", strings.Join(msgs, "\n  "))
}
