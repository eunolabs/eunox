// Copyright 2026 Eunolabs, LLC
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckRedisHA_NonProduction(t *testing.T) {
	// In non-production, single-node Redis is fine.
	urls := map[string]string{
		"REDIS_URL": "redis://localhost:6379",
	}
	errs := CheckRedisHA(EnvDevelopment, urls)
	assert.Empty(t, errs)

	errs = CheckRedisHA(EnvStaging, urls)
	assert.Empty(t, errs)
}

func TestCheckRedisHA_Production_SingleNode_Fails(t *testing.T) {
	urls := map[string]string{
		"REDIS_URL": "redis://redis.internal:6379",
	}
	errs := CheckRedisHA(EnvProduction, urls)
	require.Len(t, errs, 1)
	assert.Equal(t, "REDIS_URL", errs[0].EnvVar)
	assert.Contains(t, errs[0].Reason, "single-node Redis is not allowed in production")
}

func TestCheckRedisHA_Production_SingleNodeTLS_Fails(t *testing.T) {
	urls := map[string]string{
		"REDIS_URL": "rediss://redis.internal:6380",
	}
	errs := CheckRedisHA(EnvProduction, urls)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Reason, "single-node Redis is not allowed")
}

func TestCheckRedisHA_Production_Sentinel_Passes(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"redis-sentinel scheme", "redis-sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379/mymaster"},
		{"redis+sentinel scheme", "redis+sentinel://sentinel1:26379,sentinel2:26379/mymaster"},
		{"rediss+sentinel scheme", "rediss+sentinel://sentinel1:26379,sentinel2:26379/mymaster"},
		{"sentinel query param", "redis://sentinel1:26379?sentinel_master_name=mymaster"},
		{"sentinel query param camelCase", "redis://sentinel1:26379?sentinelMasterName=mymaster"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := map[string]string{
				"REDIS_URL": tt.url,
			}
			errs := CheckRedisHA(EnvProduction, urls)
			assert.Empty(t, errs, "URL %q should be accepted as HA", tt.url)
		})
	}
}

func TestCheckRedisHA_Production_Cluster_Passes(t *testing.T) {
	urls := map[string]string{
		"REDIS_URL": "redis-cluster://node1:6379,node2:6379,node3:6379",
	}
	errs := CheckRedisHA(EnvProduction, urls)
	assert.Empty(t, errs)
}

func TestCheckRedisHA_Production_MultipleHosts_Passes(t *testing.T) {
	urls := map[string]string{
		"REDIS_URL": "redis://node1:6379,node2:6379,node3:6379",
	}
	errs := CheckRedisHA(EnvProduction, urls)
	assert.Empty(t, errs)
}

func TestCheckRedisHA_Production_EmptyURL_Skipped(t *testing.T) {
	urls := map[string]string{
		"REDIS_URL":            "",
		"REVOCATION_REDIS_URL": "",
	}
	errs := CheckRedisHA(EnvProduction, urls)
	assert.Empty(t, errs)
}

func TestCheckRedisHA_Production_MultipleURLs(t *testing.T) {
	urls := map[string]string{
		"REDIS_URL":              "redis://single:6379",
		"REVOCATION_REDIS_URL":   "redis-sentinel://s1:26379/mymaster",
		"KILL_SWITCH_REDIS_URL":  "redis://another-single:6379",
		"CALL_COUNTER_REDIS_URL": "",
	}
	errs := CheckRedisHA(EnvProduction, urls)
	require.Len(t, errs, 2)

	envVars := make(map[string]bool)
	for _, e := range errs {
		envVars[e.EnvVar] = true
	}
	assert.True(t, envVars["REDIS_URL"])
	assert.True(t, envVars["KILL_SWITCH_REDIS_URL"])
}

func TestCheckGatewayRedisHA_Production(t *testing.T) {
	cfg := GatewayConfig{
		NodeEnv:  EnvProduction,
		RedisURL: "redis://single:6379",
	}
	err := CheckGatewayRedisHA(&cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "production Redis HA validation failed")
}

func TestCheckGatewayRedisHA_NonProduction(t *testing.T) {
	cfg := GatewayConfig{
		NodeEnv:  EnvDevelopment,
		RedisURL: "redis://single:6379",
	}
	err := CheckGatewayRedisHA(&cfg)
	assert.NoError(t, err)
}

func TestCheckGatewayRedisHA_AllHA(t *testing.T) {
	cfg := GatewayConfig{
		NodeEnv:             EnvProduction,
		RedisURL:            "redis-sentinel://s1:26379,s2:26379/mymaster",
		RevocationRedisURL:  "redis-cluster://n1:6379,n2:6379,n3:6379",
		KillSwitchRedisURL:  "redis+sentinel://s1:26379/master",
		CallCounterRedisURL: "redis://node1:6379,node2:6379",
	}
	err := CheckGatewayRedisHA(&cfg)
	assert.NoError(t, err)
}

func TestRedactURL(t *testing.T) {
	testURL := "redis://user:mysecret@host:6379/0" //nolint:gosec // test fixture
	result := redactURL(testURL)
	assert.Contains(t, result, "user")
	assert.NotContains(t, result, "mysecret")

	// Unparseable URLs are handled gracefully.
	result = redactURL("://invalid")
	assert.Equal(t, "<unparseable>", result)
}

func TestContainsMultipleHosts(t *testing.T) {
	assert.True(t, containsMultipleHosts("redis://h1:6379,h2:6379"))
	assert.True(t, containsMultipleHosts("******h1:6379,h2:6379/0"))
	assert.False(t, containsMultipleHosts("redis://h1:6379/0"))
	assert.False(t, containsMultipleHosts("******h1:6379"))
}
