#!/bin/sh
# Euno Tool Gateway — smoke-test script
#
# Exercises the core gateway endpoints to verify the local stack is healthy
# after docker compose startup.  Designed to run inside the Alpine/curl
# container defined in infra/docker-compose.yml (smoke profile), but can
# also be run manually against a running gateway:
#
#   GATEWAY_URL=http://localhost:3002 sh infra/smoke-test.sh
#
# Exit codes
#   0 — all checks passed
#   1 — one or more checks failed
#
# Environment variables
#   GATEWAY_URL     — base URL of the gateway (default: http://localhost:3002)
#   ISSUER_JWKS_URL — JWKS endpoint used to verify the issuer is healthy
#                     (default: http://localhost:3001/.well-known/jwks.json)

set -e

GATEWAY_URL="${GATEWAY_URL:-http://localhost:3002}"
ISSUER_JWKS_URL="${ISSUER_JWKS_URL:-http://localhost:3001/.well-known/jwks.json}"

PASS=0
FAIL=0

# ── Helpers ──────────────────────────────────────────────────────────────────

check() {
  label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf "[PASS] %s\n" "$label"
    PASS=$((PASS + 1))
  else
    printf "[FAIL] %s\n" "$label"
    FAIL=$((FAIL + 1))
  fi
}

check_status() {
  label="$1"
  expected="$2"
  shift 2
  actual=$(curl -o /dev/null -s -w "%{http_code}" "$@")
  if [ "$actual" = "$expected" ]; then
    printf "[PASS] %s (HTTP %s)\n" "$label" "$actual"
    PASS=$((PASS + 1))
  else
    printf "[FAIL] %s (expected HTTP %s, got %s)\n" "$label" "$expected" "$actual"
    FAIL=$((FAIL + 1))
  fi
}

check_json_field() {
  label="$1"
  url="$2"
  field="$3"
  body=$(curl -s "$url")
  # Use grep to avoid a jq dependency in the Alpine/curl image.
  if echo "$body" | grep -q "\"${field}\""; then
    printf "[PASS] %s (field '%s' present)\n" "$label" "$field"
    PASS=$((PASS + 1))
  else
    printf "[FAIL] %s (field '%s' missing in: %s)\n" "$label" "$field" "$body"
    FAIL=$((FAIL + 1))
  fi
}

printf "=== Euno Smoke Test ===\n"
printf "Gateway: %s\n" "$GATEWAY_URL"
printf "Issuer JWKS: %s\n" "$ISSUER_JWKS_URL"
printf "\n"

# ── Gateway health ────────────────────────────────────────────────────────────
printf "-- Gateway health --\n"

check_status "GET /health → 200" "200" "${GATEWAY_URL}/health"
check_status "GET /health/live → 200" "200" "${GATEWAY_URL}/health/live"
check_status "GET /health/ready → 200" "200" "${GATEWAY_URL}/health/ready"

# ── Issuer JWKS ────────────────────────────────────────────────────────────────
printf "\n-- Capability Issuer JWKS --\n"

check_status "GET /jwks.json → 200" "200" "${ISSUER_JWKS_URL}"
check_json_field "JWKS has 'keys' array" "${ISSUER_JWKS_URL}" "keys"

# ── Gateway rejects unauthenticated requests ──────────────────────────────────
printf "\n-- Authentication enforcement --\n"

check_status "POST /api/v1/tools/invoke (no auth) → 401" "401" \
  -X POST "${GATEWAY_URL}/api/v1/tools/invoke" \
  -H "Content-Type: application/json" \
  -d '{"toolName":"test","arguments":{}}'

check_status "POST /api/v1/enforce (no auth) → 401" "401" \
  -X POST "${GATEWAY_URL}/api/v1/enforce" \
  -H "Content-Type: application/json" \
  -H "X-Euno-Protocol-Version: 1" \
  -d '{"sessionId":"smoke","toolName":"test","arguments":{}}'

# ── Metrics endpoint ──────────────────────────────────────────────────────────
printf "\n-- Prometheus metrics --\n"

check_status "GET /metrics → 200" "200" "${GATEWAY_URL}/metrics"
METRICS_TMP=$(mktemp)
check "GET /metrics contains gateway counter" \
  curl -sf "${GATEWAY_URL}/metrics" -o "${METRICS_TMP}"
if [ -s "${METRICS_TMP}" ]; then
  check "metrics: euno_gateway_decisions_total present" \
    grep -q "euno_gateway_decisions_total" "${METRICS_TMP}"
fi
rm -f "${METRICS_TMP}"

# ── Validate endpoint ─────────────────────────────────────────────────────────
printf "\n-- Validation endpoint --\n"

check_status "POST /api/v1/validate (no auth) → 401" "401" \
  -X POST "${GATEWAY_URL}/api/v1/validate" \
  -H "Content-Type: application/json" \
  -d '{"toolName":"test"}'

# ── Summary ────────────────────────────────────────────────────────────────────
printf "\n=== Results: %d passed, %d failed ===\n" "$PASS" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
