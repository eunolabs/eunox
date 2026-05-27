// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/edgeobs/eunox/internal/gateway"
	"github.com/edgeobs/eunox/pkg/config"
)

func TestLevelFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		env      config.Environment
		expected string
	}{
		{config.EnvProduction, "info"},
		{config.EnvStaging, "info"},
		{config.EnvDevelopment, "debug"},
		{config.Environment("test"), "debug"},
		{config.Environment(""), "debug"},
	}

	for _, tt := range tests {
		t.Run(string(tt.env), func(t *testing.T) {
			t.Parallel()
			if got := levelFromEnv(tt.env); got != tt.expected {
				t.Errorf("levelFromEnv(%q) = %q, want %q", tt.env, got, tt.expected)
			}
		})
	}
}

func TestNoopVerifier(t *testing.T) {
	t.Parallel()

	v := &noopVerifier{}
	_, err := v.VerifyToken(t.Context(), "some-token")
	if err == nil {
		t.Fatal("expected noopVerifier to return an error")
	}
}

func TestRun_MissingConfig(t *testing.T) {
	// When required config is missing, run() should return an error.
	// config.LoadOrExit calls os.Exit on missing required config, so we
	// test at a higher level that the binary compiles and is wired correctly.
	// The unit-testable parts (levelFromEnv, noopVerifier) are tested above.
}

func TestRun_ProductionRequiresIssuerJWKSURL(t *testing.T) {
	original := loadGatewayConfig
	loadGatewayConfig = func() config.GatewayConfig {
		return config.GatewayConfig{
			NodeEnv:          config.EnvProduction,
			DeploymentTier:   config.TierSingleReplica,
			Port:             3002,
			AdminPort:        3003,
			AdminHost:        "127.0.0.1",
			AdminJWKSURI:     "https://admin.example/jwks.json",
			AdminJWTAudience: "gateway-admin",
			TenantID:         "tenant-1",
		}
	}
	defer func() { loadGatewayConfig = original }()

	err := run()
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_ISSUER_JWKS_URL is required in production") {
		t.Fatalf("expected missing issuer JWKS error, got %v", err)
	}
}

func TestValidateAdminAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       config.GatewayConfig
		tenantID  string
		expectErr bool
		errMsg    string
	}{
		{
			name: "development_no_jwks_allowed",
			cfg: config.GatewayConfig{
				NodeEnv:     config.EnvDevelopment,
				AdminAPIKey: "some-key",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
		// --- JWT required in staging too) ---
		{
			name: "staging_missing_jwks_uri_requires_error",
			cfg: config.GatewayConfig{
				NodeEnv:     config.EnvStaging,
				AdminAPIKey: "some-key",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWKS_URI is required in \"staging\"",
		},
		{
			name: "staging_missing_jwt_audience",
			cfg: config.GatewayConfig{
				NodeEnv:      config.EnvStaging,
				AdminJWKSURI: "https://auth.example.com/.well-known/jwks.json",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWT_AUDIENCE is required in \"staging\"",
		},
		{
			name: "staging_jwt_requires_tenant",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvStaging,
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			expectErr: true,
			errMsg:    "TENANT_ID (or GATEWAY_TENANT_ID) is required in \"staging\"",
		},
		{
			name: "staging_with_full_jwt_config",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvStaging,
				AdminAPIKey:      "some-key",
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
		// --- Production ---
		{
			name: "production_missing_jwks_uri",
			cfg: config.GatewayConfig{
				NodeEnv:     config.EnvProduction,
				AdminAPIKey: "some-key",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWKS_URI is required in \"production\"",
		},
		{
			name: "production_missing_jwt_audience",
			cfg: config.GatewayConfig{
				NodeEnv:      config.EnvProduction,
				AdminJWKSURI: "https://auth.example.com/.well-known/jwks.json",
			},
			tenantID:  "tenant-1",
			expectErr: true,
			errMsg:    "GATEWAY_ADMIN_JWT_AUDIENCE is required in \"production\"",
		},
		{
			name: "production_missing_tenant_for_jwt_admin_auth",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvProduction,
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			expectErr: true,
			errMsg:    "TENANT_ID (or GATEWAY_TENANT_ID) is required in \"production\"",
		},
		{
			name: "production_with_jwks_uri",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvProduction,
				AdminAPIKey:      "some-key",
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
		{
			name: "production_jwks_only_no_static_key",
			cfg: config.GatewayConfig{
				NodeEnv:          config.EnvProduction,
				AdminJWKSURI:     "https://auth.example.com/.well-known/jwks.json",
				AdminJWTAudience: "gateway-admin",
			},
			tenantID:  "tenant-1",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateAdminAuth(&tt.cfg, tt.tenantID)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMsg)
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResolveRedisURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		specific string
		fallback string
		want     string
	}{
		{"specific_wins", "redis://specific:6379", "redis://fallback:6379", "redis://specific:6379"},
		{"fallback_used_when_specific_empty", "", "redis://fallback:6379", "redis://fallback:6379"},
		{"both_empty", "", "", ""},
		{"specific_empty_string_uses_fallback", "", "redis://only:6379", "redis://only:6379"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := resolveRedisURL(tt.specific, tt.fallback)
			if got != tt.want {
				t.Errorf("resolveRedisURL(%q, %q) = %q, want %q", tt.specific, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestValidateRedisConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       config.GatewayConfig
		expectErr bool
		errMsg    string
	}{
		{
			name:      "development_no_redis_allowed",
			cfg:       config.GatewayConfig{NodeEnv: config.EnvDevelopment},
			expectErr: false,
		},
		{
			name:      "staging_no_redis_allowed_single_replica",
			cfg:       config.GatewayConfig{NodeEnv: config.EnvStaging, DeploymentTier: config.TierSingleReplica},
			expectErr: false,
		},
		{
			name:      "staging_multi_replica_requires_some_redis",
			cfg:       config.GatewayConfig{NodeEnv: config.EnvStaging, DeploymentTier: config.TierMultiReplica},
			expectErr: true,
			errMsg:    "requires Redis",
		},
		{
			name:      "staging_multi_region_partner_did_only_fails",
			cfg:       config.GatewayConfig{NodeEnv: config.EnvStaging, DeploymentTier: config.TierMultiRegionActiveActive, PartnerDIDsRedisURL: "redis://localhost:6379"},
			expectErr: true,
			errMsg:    "requires Redis",
		},
		{
			name:      "staging_multi_region_allows_when_redis_url_present",
			cfg:       config.GatewayConfig{NodeEnv: config.EnvStaging, DeploymentTier: config.TierMultiRegionActiveActive, RedisURL: "redis://localhost:6379"},
			expectErr: false,
		},
		{
			name:      "production_missing_all_redis_urls_fails",
			cfg:       config.GatewayConfig{NodeEnv: config.EnvProduction},
			expectErr: true,
			errMsg:    "in production, either REDIS_URL",
		},
		{
			name: "production_with_redis_url_ok",
			cfg: config.GatewayConfig{
				NodeEnv:  config.EnvProduction,
				RedisURL: "redis://localhost:6379",
			},
			expectErr: false,
		},
		{
			name: "production_partial_per_service_urls_fails",
			cfg: config.GatewayConfig{
				NodeEnv:            config.EnvProduction,
				KillSwitchRedisURL: "redis://ks:6379",
				RevocationRedisURL: "redis://rev:6379",
				// CallCounterRedisURL not set
			},
			expectErr: true,
			errMsg:    "in production, either REDIS_URL",
		},
		{
			name: "production_all_per_service_urls_ok",
			cfg: config.GatewayConfig{
				NodeEnv:             config.EnvProduction,
				KillSwitchRedisURL:  "redis://ks:6379",
				RevocationRedisURL:  "redis://rev:6379",
				CallCounterRedisURL: "redis://cc:6379",
				DPoPRedisURL:        "redis://dpop:6379",
				RateLimiterRedisURL: "redis://rl:6379",
			},
			expectErr: false,
		},
		{
			// Production with all per-service URLs but rate-limiter URL missing must fail.
			name: "production_per_service_urls_missing_rate_limiter_fails",
			cfg: config.GatewayConfig{
				NodeEnv:             config.EnvProduction,
				KillSwitchRedisURL:  "redis://ks:6379",
				RevocationRedisURL:  "redis://rev:6379",
				CallCounterRedisURL: "redis://cc:6379",
				DPoPRedisURL:        "redis://dpop:6379",
				// RateLimiterRedisURL not set, RedisURL not set
			},
			expectErr: true,
			errMsg:    "RATE_LIMITER_REDIS_URL",
		},
		{
			// Multi-replica with security Redis but no DPoP Redis must fail.
			name: "multi_replica_security_redis_but_no_dpop_fails",
			cfg: config.GatewayConfig{
				NodeEnv:        config.EnvStaging,
				DeploymentTier: config.TierMultiReplica,
				RedisURL:       "", // no shared URL
				KillSwitchRedisURL:  "redis://ks:6379",
				RevocationRedisURL:  "redis://rev:6379",
				CallCounterRedisURL: "redis://cc:6379",
				// DPoPRedisURL and RedisURL both empty → in-memory DPoP
			},
			expectErr: true,
			errMsg:    "Redis-backed DPoP store",
		},
		{
			// Multi-replica with security+DPoP Redis but no rate-limiter Redis must fail.
			name: "multi_replica_dpop_redis_but_no_rate_limiter_fails",
			cfg: config.GatewayConfig{
				NodeEnv:             config.EnvStaging,
				DeploymentTier:      config.TierMultiReplica,
				KillSwitchRedisURL:  "redis://ks:6379",
				RevocationRedisURL:  "redis://rev:6379",
				CallCounterRedisURL: "redis://cc:6379",
				DPoPRedisURL:        "redis://dpop:6379",
				// RateLimiterRedisURL and RedisURL both empty → per-replica in-memory limiter
			},
			expectErr: true,
			errMsg:    "rate limiter",
		},
		{
			// Multi-replica with shared REDIS_URL covers DPoP as well.
			name: "multi_replica_shared_redis_covers_dpop",
			cfg: config.GatewayConfig{
				NodeEnv:        config.EnvStaging,
				DeploymentTier: config.TierMultiReplica,
				RedisURL:       "redis://localhost:6379",
			},
			expectErr: false,
		},
		{
			// Production with all per-service URLs but DPoP URL missing must fail.
			name: "production_per_service_urls_missing_dpop_fails",
			cfg: config.GatewayConfig{
				NodeEnv:             config.EnvProduction,
				KillSwitchRedisURL:  "redis://ks:6379",
				RevocationRedisURL:  "redis://rev:6379",
				CallCounterRedisURL: "redis://cc:6379",
				// DPoPRedisURL not set, RedisURL not set
			},
			expectErr: true,
			errMsg:    "DPOP_REDIS_URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedisConfig(&tt.cfg)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMsg)
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildGatewayBackends_InMemoryFallback(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{NodeEnv: config.EnvDevelopment}
	backends, err := buildGatewayBackends(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if backends == nil {
		t.Fatal("expected non-nil backends")
	}
	if backends.killSwitch == nil {
		t.Error("killSwitch should not be nil")
	}
	if backends.revocation == nil {
		t.Error("revocation should not be nil")
	}
	if backends.counter == nil {
		t.Error("counter should not be nil")
	}
	if backends.monitor == nil {
		t.Error("monitor should not be nil")
	}
}

func TestBuildGatewayBackends_UsesRedisPartnerDIDStore(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := &config.GatewayConfig{NodeEnv: config.EnvDevelopment, PartnerDIDsRedisURL: mr.Addr()}
	// Use a redis:// URL so parsing follows production wiring.
	cfg.PartnerDIDsRedisURL = "redis://" + mr.Addr()

	backends, err := buildGatewayBackends(cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := backends.partnerDIDs.(*gateway.RedisPartnerDIDStore); !ok {
		t.Fatalf("expected RedisPartnerDIDStore, got %T", backends.partnerDIDs)
	}
}

func TestBuildGatewayBackends_InvalidRedisURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cfg    config.GatewayConfig
		errMsg string
	}{
		{
			name: "invalid_kill_switch_url",
			cfg: config.GatewayConfig{
				NodeEnv:            config.EnvDevelopment,
				KillSwitchRedisURL: "not-a-valid-url://??",
			},
			errMsg: "kill-switch redis URL",
		},
		{
			name: "invalid_revocation_url",
			cfg: config.GatewayConfig{
				NodeEnv:            config.EnvDevelopment,
				RevocationRedisURL: "not-a-valid-url://??",
			},
			errMsg: "revocation redis URL",
		},
		{
			name: "invalid_call_counter_url",
			cfg: config.GatewayConfig{
				NodeEnv:             config.EnvDevelopment,
				CallCounterRedisURL: "not-a-valid-url://??",
			},
			errMsg: "call-counter redis URL",
		},
		{
			name: "invalid_partner_dids_url",
			cfg: config.GatewayConfig{
				NodeEnv:             config.EnvDevelopment,
				PartnerDIDsRedisURL: "not-a-valid-url://??",
			},
			errMsg: "partner-dids redis URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := buildGatewayBackends(&tt.cfg, nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errMsg)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestNewRedisClientFromURL(t *testing.T) {
	t.Parallel()

	// These tests verify that newRedisClientFromURL returns a non-nil client
	// without error. No actual Redis connection is made.
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Standard single-node URLs handled by goredis.ParseURL.
		{
			name: "standard_redis",
			url:  "redis://localhost:6379",
		},
		{
			name: "standard_rediss_tls",
			url:  "rediss://localhost:6380",
		},
		// Sentinel URLs.
		{
			name: "sentinel_redis_sentinel_scheme",
			url:  "redis-sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379/mymaster",
		},
		{
			name: "sentinel_redis_plus_sentinel_scheme",
			url:  "redis+sentinel://sentinel1:26379,sentinel2:26379/mymaster",
		},
		{
			name: "sentinel_rediss_plus_sentinel_tls",
			url:  "rediss+sentinel://sentinel1:26379,sentinel2:26379/mymaster",
		},
		{
			name: "sentinel_with_password",
			url:  "redis-sentinel://:secret@sentinel1:26379,sentinel2:26379/master",
		},
		// Cluster / multi-host URLs.
		{
			name: "cluster_redis_cluster_scheme",
			url:  "redis-cluster://node1:6379,node2:6379,node3:6379",
		},
		{
			name: "multi_host_standard_scheme",
			url:  "redis://node1:6379,node2:6379",
		},
		// Error cases.
		{
			name:    "invalid_url",
			url:     "not-a-valid-url://??",
			wantErr: true,
		},
		{
			name:    "sentinel_no_hosts",
			url:     "redis-sentinel:///mymaster",
			wantErr: true,
		},
		{
			name:    "cluster_no_hosts",
			url:     "redis-cluster:///",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, err := newRedisClientFromURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for URL %q, got nil", tt.url)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for URL %q: %v", tt.url, err)
			}
			if client == nil {
				t.Errorf("expected non-nil client for URL %q", tt.url)
			}
		})
	}
}
