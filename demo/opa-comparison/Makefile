# Copyright 2026 Eunolabs, LLC
# SPDX-License-Identifier: Apache-2.0
#
# demo/opa-comparison/Makefile
#
# Usage (from repo root):
#   make -C demo/opa-comparison scenario-1
#   make -C demo/opa-comparison scenario-2
#   make -C demo/opa-comparison scenario-3
#   make -C demo/opa-comparison down
#
# Or from this directory:
#   make scenario-1
#   make scenario-2
#   make scenario-3

SHELL    := /usr/bin/env bash
DEMO_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DC       := docker compose -f "$(DEMO_DIR)docker-compose.yml"

.PHONY: scenario-1 scenario-2 scenario-3 up down logs help _audit-dir

# _run-scenario <manifest> <script>
# Starts the stack, runs the script, and always tears down afterwards.
# The exit status of the script is preserved so make reports failure correctly.
define _run-scenario
	@mkdir -p "$(DEMO_DIR)audit" && chmod 777 "$(DEMO_DIR)audit"
	@echo "==> Starting stack with $(1) manifest …"
	@EUNOX_MANIFEST=$(1) $(DC) up --build --force-recreate -d --wait \
	  && bash "$(DEMO_DIR)scripts/$(2)"; STATUS=$$?; \
	  $(DC) down --remove-orphans; exit $$STATUS
endef

## scenario-1: Credential exfiltration — OPA allows unlimited; eunox enforces maxCalls:1
scenario-1:
	$(call _run-scenario,scenario1.yaml,scenario1.sh)

## scenario-2: Path-gated file access — OPA requires O(tools) rules; eunox uses one wildcard
scenario-2:
	$(call _run-scenario,scenario2.yaml,scenario2.sh)

## scenario-3: Short-lived token reuse — OPA allows accumulation; eunox blocks after maxCalls:1
scenario-3:
	$(call _run-scenario,scenario3.yaml,scenario3.sh)

## up: Start the stack with scenario1 manifest (default) in the foreground.
##     Override: EUNOX_MANIFEST=scenario2.yaml make up
up: _audit-dir
	EUNOX_MANIFEST=$${EUNOX_MANIFEST:-scenario1.yaml} $(DC) up --build

## down: Stop and remove the stack.
down:
	$(DC) down --remove-orphans

## logs: Tail all container logs.
logs:
	$(DC) logs -f

## help: Show this help.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //'

# Internal: ensure audit dir exists and is world-writable.
_audit-dir:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
