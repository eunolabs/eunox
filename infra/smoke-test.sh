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
#   ISSUER_URL      — base URL of the capability issuer (default: http://localhost:3001)
#   ISSUER_JWKS_URL — JWKS endpoint used to verify the issuer is healthy
#                     (default: http://localhost:3001/.well-known/jwks.json)
#   MOCK_OIDC_URL   — base URL of the mock OIDC server, present only in the
#                     smoke Docker Compose profile; when set the issuance
#                     round-trip section is executed (default: unset → skipped)

set -u

GATEWAY_URL="${GATEWAY_URL:-http://localhost:3002}"
ISSUER_URL="${ISSUER_URL:-http://localhost:3001}"
ISSUER_JWKS_URL="${ISSUER_JWKS_URL:-http://localhost:3001/.well-known/jwks.json}"
MOCK_OIDC_URL="${MOCK_OIDC_URL:-}"

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
  # Use || true so a connection error reports [FAIL] rather than aborting.
  actual=$(curl -o /dev/null -s -w "%{http_code}" "$@" || true)
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
  # Use || true so a connection error reports [FAIL] rather than aborting.
  body=$(curl -s "$url" || true)
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
if [ -n "$MOCK_OIDC_URL" ]; then
  printf "Mock OIDC: %s\n" "$MOCK_OIDC_URL"
fi
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

# ── Issuance round-trip (smoke profile only) ───────────────────────────────
# Requires MOCK_OIDC_URL to be set (set by docker-compose when mock-oidc is
# running in the smoke profile).  Skipped when running the script outside of
# Docker Compose (e.g. in a CI environment without the mock OIDC server).
if [ -n "$MOCK_OIDC_URL" ]; then
  printf "\n-- Issuance round-trip --\n"

  # Use a unique nonce so each smoke run can't replay a previous token.
  SMOKE_NONCE="smoke-$(date +%s%N 2>/dev/null || echo "${RANDOM}$(date +%s)")"

  # Step 1: mint a test ID token from the mock OIDC server.
  MINT_RESP=$(curl -s -X POST "${MOCK_OIDC_URL}/token" \
    -H "Content-Type: application/json" \
    -d "{\"nonce\":\"${SMOKE_NONCE}\",\"groups\":[\"developer\"],\"sub\":\"smoke-test-user\"}" \
    || true)

  # Extract id_token from the JSON response using grep/sed (no jq available).
  ID_TOKEN=$(printf '%s' "$MINT_RESP" | grep -o '"id_token":"[^"]*"' | sed 's/"id_token":"//;s/"$//' || true)

  if [ -n "$ID_TOKEN" ]; then
    printf "[PASS] Mock OIDC: minted test ID token\n"
    PASS=$((PASS + 1))
  else
    printf "[FAIL] Mock OIDC: could not mint test ID token (response: %s)\n" "$MINT_RESP"
    FAIL=$((FAIL + 1))
  fi

  # Step 2: exchange the ID token at the capability issuer.
  if [ -n "$ID_TOKEN" ]; then
    ISSUE_RESP=$(curl -s -X POST "${ISSUER_URL}/api/v1/oidc/token" \
      -H "Content-Type: application/json" \
      -d "{\"idToken\":\"${ID_TOKEN}\",\"nonce\":\"${SMOKE_NONCE}\",\"agentId\":\"smoke-agent\"}" \
      || true)

    CAP_TOKEN=$(printf '%s' "$ISSUE_RESP" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"$//' || true)

    if [ -n "$CAP_TOKEN" ]; then
      printf "[PASS] Issuer: exchanged ID token for capability token\n"
      PASS=$((PASS + 1))
    else
      printf "[FAIL] Issuer: capability token exchange failed (response: %s)\n" "$ISSUE_RESP"
      FAIL=$((FAIL + 1))
    fi

    # Step 3: present the capability token to the gateway enforce endpoint.
    if [ -n "$CAP_TOKEN" ]; then
      check_status "Gateway: enforce with capability token → 200" "200" \
        -X POST "${GATEWAY_URL}/api/v1/enforce" \
        -H "Authorization: Bearer ${CAP_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "X-Euno-Protocol-Version: 1" \
        -d '{"sessionId":"smoke-issuance","toolName":"smoke-tool","arguments":{}}'
    fi
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────
printf "\n=== Results: %d passed, %d failed ===\n" "$PASS" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
