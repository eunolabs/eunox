// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"crypto/tls"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"
)

// newRedisClientFromURL creates a redis.Cmdable from a URL string.
//
// Unlike goredis.ParseURL, it supports HA URL schemes:
//   - redis-sentinel:// / redis+sentinel:// / rediss+sentinel://
//     Format: <scheme>://[:password@]host1:port,host2:port/masterName
//   - redis-cluster://
//     Format: redis-cluster://[:password@]host1:port,host2:port
//   - Comma-separated hosts in a standard redis:// URL (treated as cluster)
//   - Standard redis:// and rediss:// single-node URLs
func newRedisClientFromURL(rawURL string) (goredis.Cmdable, error) {
	trimmed := strings.TrimSpace(rawURL)
	lower := strings.ToLower(trimmed)

	switch {
	case strings.HasPrefix(lower, "redis-sentinel://"),
		strings.HasPrefix(lower, "redis+sentinel://"),
		strings.HasPrefix(lower, "rediss+sentinel://"):
		return parseSentinelURL(trimmed)
	case strings.HasPrefix(lower, "redis-cluster://"):
		return parseClusterOrMultiHostURL(trimmed, "redis-cluster://")
	default:
		if containsMultipleHosts(trimmed) {
			// A standard redis:// with comma-separated hosts is treated as a
			// cluster/multi-primary setup via UniversalClient.
			scheme := "redis://"
			if idx := strings.Index(trimmed, "://"); idx >= 0 {
				scheme = trimmed[:idx+3]
			}
			return parseClusterOrMultiHostURL(trimmed, scheme)
		}
		opts, err := goredis.ParseURL(trimmed)
		if err != nil {
			return nil, err
		}
		return goredis.NewClient(opts), nil
	}
}

// parseSentinelURL parses redis-sentinel://, redis+sentinel://, or
// rediss+sentinel:// URLs and returns a UniversalClient in sentinel mode.
//
// Expected format:
//
//	<scheme>://[:password@]sentinel1:port,sentinel2:port[/masterName]
func parseSentinelURL(rawURL string) (goredis.Cmdable, error) {
	lower := strings.ToLower(rawURL)

	var schemeLen int
	var useTLS bool
	switch {
	case strings.HasPrefix(lower, "redis-sentinel://"):
		schemeLen = len("redis-sentinel://")
	case strings.HasPrefix(lower, "redis+sentinel://"):
		schemeLen = len("redis+sentinel://")
	case strings.HasPrefix(lower, "rediss+sentinel://"):
		schemeLen = len("rediss+sentinel://")
		useTLS = true
	default:
		return nil, fmt.Errorf("unrecognized sentinel scheme in URL")
	}

	after := rawURL[schemeLen:]

	// Extract optional password (last @ separates userinfo from host).
	var password string
	if idx := strings.LastIndex(after, "@"); idx >= 0 {
		userInfo := after[:idx]
		after = after[idx+1:]
		if colonIdx := strings.Index(userInfo, ":"); colonIdx >= 0 {
			password = userInfo[colonIdx+1:]
		} else {
			password = userInfo
		}
	}

	// Split hosts from optional /masterName[?query] path.
	hostsStr := after
	masterName := "mymaster"
	if pathIdx := strings.Index(after, "/"); pathIdx >= 0 {
		hostsStr = after[:pathIdx]
		pathStr := after[pathIdx+1:]
		// Strip query string.
		if qIdx := strings.Index(pathStr, "?"); qIdx >= 0 {
			pathStr = pathStr[:qIdx]
		}
		if pathStr != "" {
			masterName = pathStr
		}
	}

	addrs := splitHosts(hostsStr)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no sentinel addresses found in URL")
	}

	opts := &goredis.UniversalOptions{
		Addrs:      addrs,
		MasterName: masterName,
		Password:   password,
	}
	if useTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	return goredis.NewUniversalClient(opts), nil
}

// parseClusterOrMultiHostURL parses a redis-cluster:// URL or a standard
// redis:// URL with comma-separated hosts, returning a UniversalClient in
// cluster mode (no MasterName set).
//
// Expected format:
//
//	<scheme>://[:password@]host1:port,host2:port[/db]
func parseClusterOrMultiHostURL(rawURL, scheme string) (goredis.Cmdable, error) {
	schemeLen := len(scheme)
	after := rawURL
	if len(rawURL) >= schemeLen && strings.EqualFold(rawURL[:schemeLen], scheme) {
		after = rawURL[schemeLen:]
	} else if idx := strings.Index(rawURL, "://"); idx >= 0 {
		after = rawURL[idx+3:]
	}

	// Extract optional password.
	var password string
	if idx := strings.LastIndex(after, "@"); idx >= 0 {
		userInfo := after[:idx]
		after = after[idx+1:]
		if colonIdx := strings.Index(userInfo, ":"); colonIdx >= 0 {
			password = userInfo[colonIdx+1:]
		} else {
			password = userInfo
		}
	}

	// Strip path and query; they are not meaningful for cluster mode.
	hostsStr := after
	if idx := strings.IndexAny(after, "/?"); idx >= 0 {
		hostsStr = after[:idx]
	}

	addrs := splitHosts(hostsStr)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found in Redis cluster URL")
	}

	opts := &goredis.UniversalOptions{
		Addrs:    addrs,
		Password: password,
	}

	return goredis.NewUniversalClient(opts), nil
}

// splitHosts splits a comma-separated host string into individual addresses,
// trimming whitespace and skipping empty entries.
func splitHosts(s string) []string {
	parts := strings.Split(s, ",")
	addrs := make([]string, 0, len(parts))
	for _, p := range parts {
		if h := strings.TrimSpace(p); h != "" {
			addrs = append(addrs, h)
		}
	}
	return addrs
}

// containsMultipleHosts checks if the URL has multiple comma-separated hosts.
// Duplicated here from pkg/config to avoid a cross-package dependency in main.
func containsMultipleHosts(rawURL string) bool {
	after := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		after = rawURL[idx+3:]
	}
	if idx := strings.LastIndex(after, "@"); idx >= 0 {
		after = after[idx+1:]
	}
	if idx := strings.IndexAny(after, "/?"); idx >= 0 {
		after = after[:idx]
	}
	return strings.Contains(after, ",")
}

// newRedisUniversalClientFromURL returns the Redis client as a
// [goredis.UniversalClient] (which exposes Subscribe) rather than [goredis.Cmdable].
// All concrete client types created by [newRedisClientFromURL] implement
// [goredis.UniversalClient]; the type assertion here panics at startup if the
// implementation ever changes, which is preferable to a silent runtime failure.
func newRedisUniversalClientFromURL(rawURL string) (goredis.UniversalClient, error) {
	c, err := newRedisClientFromURL(rawURL)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(goredis.UniversalClient)
	if !ok {
		return nil, fmt.Errorf("redis client type %T does not implement UniversalClient; cannot use partitioned kill-switch", c)
	}
	return uc, nil
}
