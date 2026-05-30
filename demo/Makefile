# demo/Makefile — single-command demo for eunox-mcp.
#
# Run from the repo root:
#   make -C demo up      # start the stack (manifest-only mode)
#   make -C demo allow   # allowed tool call
#   make -C demo deny    # denied tool call
#   make -C demo audit   # tail the audit log
#
# Or from inside the demo/ directory:
#   cd demo && make up

.PHONY: up up-jwt down allow deny deny-path deny-op audit jwt jwt-allow jwt-deny logs ci-test ci-test-jwt help

DEMO_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# ─────────────────────────────────────────────────────────────────────────────
# Stack lifecycle
# ─────────────────────────────────────────────────────────────────────────────

## Start the demo stack in manifest-only mode (no JWT required).
up:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
	docker compose -f "$(DEMO_DIR)docker-compose.yml" up --build -d
	@echo ""
	@echo "  eunox-mcp proxy : http://localhost:3000/mcp"
	@echo "  mock-mcp-server : http://localhost:8080/mcp"
	@echo "  Keycloak        : http://localhost:8081 (admin / admin)"
	@echo ""
	@echo "  Next: make -C demo allow   # allowed tool call"
	@echo "        make -C demo deny    # policy denial"
	@echo "        make -C demo audit   # live audit log"

## Start the demo stack in JWT + manifest intersection mode.
up-jwt:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
	docker compose \
	  -f "$(DEMO_DIR)docker-compose.yml" \
	  -f "$(DEMO_DIR)docker-compose.jwt.yml" \
	  up --build -d
	@echo ""
	@echo "  eunox-mcp (JWT mode) : http://localhost:3000/mcp"
	@echo "  Keycloak             : http://localhost:8081 (admin / admin)"
	@echo ""
	@echo "  Next: make -C demo jwt       # get a test JWT"
	@echo "        make -C demo jwt-allow # JWT-authenticated allowed call"
	@echo "        make -C demo jwt-deny  # JWT-authenticated denied call"

## Stop and remove all demo containers.
down:
	docker compose -f "$(DEMO_DIR)docker-compose.yml" down --remove-orphans

# ─────────────────────────────────────────────────────────────────────────────
# Manifest-only demo (no JWT required)
# ─────────────────────────────────────────────────────────────────────────────

## ALLOW: read_file /reports/q3.pdf → permitted by manifest (AllowedValues /reports/*)
allow:
	@echo ">>> read_file /reports/q3.pdf  [expect: ALLOWED]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}'

## DENY: write_file → absent from manifest, denied by default
deny:
	@echo ">>> write_file /etc/passwd  [expect: DENIED — not in manifest]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"hacked"}}}'

## DENY-PATH: read_file outside /reports/ → denied by AllowedValues condition
deny-path:
	@echo ">>> read_file /etc/shadow  [expect: DENIED — path not in /reports/*]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}}}'

## DENY-OP: query_db with DELETE → denied by AllowedOperations condition
deny-op:
	@echo ">>> query_db DELETE FROM reports  [expect: DENIED — only SELECT permitted]"
	@bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_db","arguments":{"query":"DELETE FROM reports"}}}'

# ─────────────────────────────────────────────────────────────────────────────
# JWT demo (requires: make up-jwt)
# ─────────────────────────────────────────────────────────────────────────────

## Print a test JWT from the local Keycloak instance (client-credentials flow).
## JWT carries: eunox.capabilities = ["read_file:/reports/*", "query_db:SELECT"]
jwt:
	@echo ">>> Fetching JWT from Keycloak (eunox-demo realm, demo-agent client)..."
	@bash "$(DEMO_DIR)scripts/get-jwt.sh"

## JWT-ALLOW: read_file with JWT carrying matching capability claim.
jwt-allow:
	@echo ">>> [JWT mode] read_file /reports/q3.pdf  [expect: ALLOWED]"
	@TOKEN=$$(bash "$(DEMO_DIR)scripts/get-jwt.sh") && \
	 bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	   '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/reports/q3.pdf"}}}' \
	   "$$TOKEN"

## JWT-DENY: write_file — absent from JWT capabilities (and from manifest).
jwt-deny:
	@echo ">>> [JWT mode] write_file /tmp/x.txt  [expect: DENIED — not in JWT capabilities]"
	@TOKEN=$$(bash "$(DEMO_DIR)scripts/get-jwt.sh") && \
	 bash "$(DEMO_DIR)scripts/mcp-call.sh" \
	   '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/x.txt","content":"hello"}}}' \
	   "$$TOKEN"

# ─────────────────────────────────────────────────────────────────────────────
# Observability
# ─────────────────────────────────────────────────────────────────────────────

## Tail the OCSF audit log (requires jq).
audit:
	@tail -f "$(DEMO_DIR)audit/audit.jsonl" | jq .

## Follow container logs for eunox-mcp.
logs:
	docker compose -f "$(DEMO_DIR)docker-compose.yml" logs -f eunox-mcp

# ─────────────────────────────────────────────────────────────────────────────
# CI integration tests (start stack → test → always tear down)
# ─────────────────────────────────────────────────────────────────────────────

## ci-test: Run manifest-only integration tests in CI (starts stack, tests, tears down).
ci-test:
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting manifest-only stack for CI tests (Keycloak skipped) ..."
	@docker compose -f "$(DEMO_DIR)docker-compose.yml" \
	  up --build --force-recreate -d --wait --scale keycloak=0 \
	  && bash "$(DEMO_DIR)scripts/ci-test.sh"; STATUS=$$?; \
	  docker compose -f "$(DEMO_DIR)docker-compose.yml" down --remove-orphans; \
	  exit $$STATUS

## ci-test-jwt: Run JWT-mode integration tests in CI (starts full stack, tests, tears down).
ci-test-jwt:
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting JWT-mode stack for CI tests (Keycloak + eunox-mcp) ..."
	@docker compose \
	  -f "$(DEMO_DIR)docker-compose.yml" \
	  -f "$(DEMO_DIR)docker-compose.jwt.yml" \
	  up --build --force-recreate -d --wait \
	  && bash "$(DEMO_DIR)scripts/ci-test-jwt.sh"; STATUS=$$?; \
	  docker compose \
	    -f "$(DEMO_DIR)docker-compose.yml" \
	    -f "$(DEMO_DIR)docker-compose.jwt.yml" \
	    down --remove-orphans; \
	  exit $$STATUS

## Print this help.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
