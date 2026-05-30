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

SHELL   := /usr/bin/env bash
DEMO_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DC       := docker compose -f "$(DEMO_DIR)docker-compose.yml"

.PHONY: scenario-1 scenario-2 scenario-3 up down logs help

## scenario-1: Credential exfiltration — OPA allows unlimited; eunox enforces maxCalls:1
scenario-1: _audit-dir
	@echo "==> Starting stack with scenario1 manifest …"
	@EUNOX_MANIFEST=scenario1.yaml $(DC) up --build --force-recreate -d --wait
	@echo "==> Running scenario 1 …"
	@bash "$(DEMO_DIR)scripts/scenario1.sh"
	@$(DC) down --remove-orphans

## scenario-2: Path-gated file access — OPA requires O(tools) rules; eunox uses one wildcard
scenario-2: _audit-dir
	@echo "==> Starting stack with scenario2 manifest …"
	@EUNOX_MANIFEST=scenario2.yaml $(DC) up --build --force-recreate -d --wait
	@echo "==> Running scenario 2 …"
	@bash "$(DEMO_DIR)scripts/scenario2.sh"
	@$(DC) down --remove-orphans

## scenario-3: Short-lived token reuse — OPA allows accumulation; eunox blocks after maxCalls:1
scenario-3: _audit-dir
	@echo "==> Starting stack with scenario3 manifest …"
	@EUNOX_MANIFEST=scenario3.yaml $(DC) up --build --force-recreate -d --wait
	@echo "==> Running scenario 3 …"
	@bash "$(DEMO_DIR)scripts/scenario3.sh"
	@$(DC) down --remove-orphans

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

# Internal: ensure audit dir exists and is world-writable for distroless UID 65534.
_audit-dir:
	@mkdir -p "$(DEMO_DIR)audit"
	@chmod 777 "$(DEMO_DIR)audit"
