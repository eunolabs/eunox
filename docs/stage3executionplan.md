Stage 3 Execution Plan — "The Gateway as Managed Boundary"
Source: docs/mvp.md §"Stage 3: The Gateway as Managed Boundary" (lines 602–697), with hard dependencies on §"Policy and audit schema parity" (lines 507–554) and §"Minter threat model" (lines 660–691).

Stage 3 thesis (preserve when assigning tasks). Stage 1–2 enforcement runs in-process inside @euno/mcp with local files, in-memory counters, an HMAC audit log, and an in-process kill switch. Stage 3 lifts enforcement out of the agent process into a hosted (and self-hostable) gateway. The agent's policy file shape and audit record shape do not change — only the implementations of four already-existing seams in @euno/common-core change, plus one new seam (LocalPolicySource → JWT loader). The user-visible upgrade is a single config change: {"enforcer":"local"} → {"enforcer":"https://gateway.euno.example","apiKey":"sk-..."}. To make that one-config-change promise true while preserving the cryptographic-token invariant, Stage 3 introduces an API-key minter in front of the existing euno-platform/packages/tool-gateway. The minter is the highest-value key in the system; it cannot ship before its written threat model is reviewed.

Ground truth pointers Copilot must read first on every task:

docs/mvp.md §"Stage 3" (lines 602–697)
docs/mvp.md §"Policy and audit schema parity" — the parity table (lines 520–528)
docs/capability-model.md §6 ("unknown types are denied by default")
docs/enforcement.md (cryptographic-token invariant)
Existing seams: public/packages/common/src/runtime.ts (TokenVerifier, EvidenceSigner, KillSwitchManager), public/packages/common/src/condition-registry.ts (CallCounterStore), public/packages/common/src/manifest-validator.ts
Existing implementations to wire/reuse: euno-platform/packages/tool-gateway/src/{verifier.ts,enforcement.ts,admin-api.ts,revocation-store.ts}, euno-platform/packages/common-infra/src/{call-counter-store.ts,redis-kill-switch.ts,redis-circuit-breaker.ts,ledger-signer.ts}, euno-platform/packages/capability-issuer/ (for token issuance reference)
Per-task obligation: any new condition handling, audit field, or token claim must be added in @euno/common-core first and consumed by @euno/mcp and tool-gateway from there. No types in @euno/mcp or tool-gateway that don't exist in @euno/common-core (per Critical Risks §"@euno/mcp" rule, lines 871–874).
Phase A — Pre-flight (gating; must complete before any code ships to a paying customer)
Task 0 — Stage 3 design freeze & RFC
Author docs/stage-3-design.md capturing: chosen KMS provider (Azure Managed HSM vs AWS CloudHSM vs GCP Cloud HSM), Postgres deployment shape for audit + revocation, Redis deployment shape, hosted-vs-self-host feature matrix, the API-key format and storage scheme (hash-at-rest, prefix indexing), and the exact request/response contract between @euno/mcp (in enforcer:"https://..." mode) and the gateway.
Cross-link every decision back to the MVP doc anchor it satisfies.
Gate: RFC reviewed and merged before Tasks 2+ start.
Task 1 — API-key minter threat model (BLOCKING per MVP lines 660–691)
Produce docs/security/minter-threat-model.md answering all seven questions in the MVP table verbatim:
Key storage (HSM choice, non-exportability verified at HSM level, not just policy — call out exact API used to assert non-exportability).
Blast radius per key compromise (per-issuance audit trail design).
Key rotation procedure including revocation of previously minted tokens.
Scope isolation (per-tenant signing key vs platform-wide; recommend per-tenant keys behind a single root if HSM cost permits).
Credential access path to the minter signing API (network isolation, mTLS, hardware attestation from caller).
Audit trail for every mint call (caller identity, tenant, policy fingerprint, resulting JWT jti) stored append-only with credentials separate from the minter.
Monitoring & alerting rules (mint-rate anomaly, off-hours mint).
Reviewed and signed off by ≥2 engineers + 1 security reviewer outside the implementer.
Gate: No minter code merges to main until this doc is approved.
Phase B — Seam swaps inside @euno/mcp (the "single config change" path)
All four tasks below preserve the Stage 1–2 path unchanged. Each swap is selected at runtime by an enforcer config value or DI factory; the existing local backends remain the default.

Task 2 — @euno/mcp enforcer mode dispatch
In public/packages/mcp/src/cli.ts and the proxy bootstrap, add an enforcer config field ("local" | { url: string, apiKey: string }, default "local").
When enforcer.url is set, skip FilePolicySource/LocalHmacSigner/InMemoryCallCounterStore/in-memory kill switch construction and instead build a RemoteEnforcer client that forwards each tools/call (and lifecycle events) to the gateway and applies the returned obligations (deny / redact / annotate).
The local LocalPolicySource interface (already in public/packages/mcp/src/policy/source.ts) is not extended here — Stage 1 wrapped the file loader behind it precisely so Stage 3 swaps the whole enforcer rather than only the policy reader. Document this explicitly in code comments (the MVP commits to drop-in replacement of the loader, but the cleaner Stage 3 boundary is at the enforcer call, not at policy read).
Tests: existing local mode unchanged; new tests for remote mode using a mock gateway.
Task 3 — JWTTokenVerifier wiring (consume, do not invent)
The verifier itself already lives in euno-platform/packages/tool-gateway/src/verifier.ts. Confirm its TokenVerifier shape matches the seam in public/packages/common/src/runtime.ts:423. If divergent, refactor the gateway to consume the seam from @euno/common-core (must not duplicate types per Critical Risks rule).
Move JWKS-client glue (tool-gateway/src/jwks-client.ts) behind the seam and register it as the production TokenVerifier in the gateway's bootstrap.
Tests: round-trip a token issued by capability-issuer against the verifier; assert that an unknown condition in the manifest is rejected at verification time (capability-model §6 invariant).
Task 4 — RedisCallCounterStore for the gateway
Use existing euno-platform/packages/common-infra/src/call-counter-store.ts (Redis impl) and redis-circuit-breaker.ts. Wire both into tool-gateway's enforcement path so rateLimit / maxCalls conditions are enforced across replicas.
Circuit-breaker behavior on Redis outage must be explicit and documented: choose fail-closed (default for the hosted offering) with operator-overridable fail-open for self-host. Encode the choice in a config field with no silent default.
Tests: multi-replica simulation showing the same counter incrementing across two gateway processes; circuit-open path returns the documented decision.
Task 5 — KMS-backed EvidenceSigner
Implement KmsEvidenceSigner in euno-platform/packages/common-infra/src/ with three drivers (Azure Key Vault, AWS KMS, GCP KMS) selected by config. Implement against the EvidenceSigner interface in public/packages/common/src/runtime.ts:111.
Audit record shape must be byte-identical to what LocalHmacSigner produces (OCSF API Activity, class_uid 6003); only the signature algorithm/keyref changes. Add a parity test that runs the same record through both signers and asserts identical canonical JSON pre-signature.
Wire as the gateway's default signer; keep LocalHmacSigner available behind a config flag for self-host development.
Task 6 — RedisKillSwitchManager with Postgres dual-write
Use existing euno-platform/packages/common-infra/src/redis-kill-switch.ts and its KillSwitchPersistenceBackend seam; implement the Postgres backend if not already present (the MVP commits to dual-write — verify and fill the gap).
Semantics: Redis is the read path (latency); Postgres is durable truth. On Redis cold-start, replay from Postgres.
Wire admin API endpoints in tool-gateway/src/admin-api.ts to the Redis+Postgres manager.
Tests: kill switch survives Redis flush; revocation list mirrors to Postgres within bounded latency.
Phase C — The hosted gateway service
Task 7 — Persistent audit query API
The audit write path uses PerReplicaPostgresLedgerBackend (already exists per MVP line 649). Add a read API: paginated, filterable by tenantId, agentId, jti, decision, time range, conditionType, denialCode. Return OCSF records as-is (do not reshape).
HTTP route under tool-gateway/src/routes/ (e.g., audit.ts). AuthN: tenant-scoped API key (same minter-issued credential used for enforcement reads).
Cross-chain anchor stays off per MVP line 650 — leave the seam in place but do not enable.
Task 8 — Admin API hardening
Audit existing tool-gateway/src/admin-api.ts endpoints (kill switch, revocation list) for: tenant scoping (cannot kill across tenants), idempotency keys, and a complete OCSF audit trail of admin actions themselves.
Add a minimal admin UI later; for Stage 3 the API + a documented curl recipe is acceptable.
Task 9 — Hosted enforcement HTTP contract (gateway side of Task 2)
Define and version the wire protocol used by @euno/mcp's remote-enforcer mode. Document in docs/stage-3-gateway-protocol.md with: request envelope (session/agent/jti/tool/args/recipients/sourceIp), response envelope (allow/deny/obligations[]), versioning header (X-Euno-Protocol-Version: 1), and error-class taxonomy.
Implement on the gateway as a route group in tool-gateway/src/routes/ (e.g., enforce.ts).
Backward-compat plan: bumping the protocol version requires a deprecation window of ≥1 minor version and a server-side translator until removal.
Phase D — The API-key minter (only after Task 1 is signed off)
Task 10 — Minter service skeleton
New package: euno-platform/packages/api-key-minter/ (BSL, hosted-only initially per MVP line 646).
Surface: POST /mint taking {apiKey, agentId, sessionId} → {capabilityToken, expiresAt}. Rate-limited per tenant.
API-key store: hashed-at-rest, prefix-indexed lookup. Issuance flow (admin) creates (prefix, hash, tenantId, policyId, scopes) rows.
Token shape: identical to capability-issuer output so the gateway's existing verifier path is unchanged.
TTL: short (≤5 min) and refreshable; the agent-side client (@euno/mcp remote-enforcer) handles refresh transparently.
Task 11 — Minter HSM integration
Implement signing via the same KMS provider chosen in Task 5; reuse the EvidenceSigner-style abstraction or a parallel TokenSigner seam (whichever already exists in @euno/common-core — verify before adding new types).
Per-tenant key isolation as defined by the threat model. Implement key-rotation procedure end-to-end with a tested runbook.
Per-mint audit row written to the immutable mint-audit store (separate credentials from the minter, per threat-model requirement).
Task 12 — Minter monitoring & alerting
Prometheus metrics: euno_minter_mint_total{tenant,result}, euno_minter_mint_latency_seconds, euno_minter_kms_error_total, euno_minter_anomaly_alerts_total.
Anomaly rules (per threat model §"Monitoring and alerting"): mint-rate spike per tenant, off-hours mint for low-activity tenants, mint failures clustering.
Alert routes documented in the SRE runbook.
Phase E — Self-host & "Bring Your Own Gateway" (BYO-GW)
Task 13 — Self-hostable Docker image
Single euno-platform/packages/tool-gateway/Dockerfile already exists; produce a published image (BSL) with: configurable backends (Redis or in-memory for dev; Postgres or SQLite for dev; local HMAC or KMS).
docker-compose.yml for the canonical local stack (gateway + Redis + Postgres). Smoke-test target.
Task 14 — BYO-GW path documentation
docs/self-host.md: what self-hosters must run themselves (issuer, gateway, Redis, Postgres, KMS-or-HMAC) and what they give up (no managed minter; they issue their own tokens via capability-issuer).
A short "minimum viable issuer" recipe so a self-host operator can produce tokens without standing up the full identity stack (Stage 4 makes this richer).
Phase F — Migration, telemetry, and the developer story
Task 15 — @euno/mcp upgrade UX
The single config change must actually work end-to-end. Build a euno-mcp upgrade-to-hosted interactive command that:
Validates an API key against the gateway.
Round-trips the user's existing local policy file to the hosted policy store via an admin API call.
Patches the user's mcp.json / claude_desktop_config.json to add enforcer.url and apiKey, with a backup.
Document the manual path too.
Task 16 — Telemetry continuity
The local-mode anonymous telemetry already counts enforcement events. Add hosted-mode equivalents server-side (per-tenant, opt-out per the existing telemetry contract). Same event names so dashboards from Stage 1–2 keep working.
Update scripts/stage4-readiness.ts (new, modeled on scripts/stage3-readiness.ts) to track Stage-4 gate signals: ≥1 paying team, ≥1 written security/compliance question. The Stage-3 gate is met when this script first reports both.
Task 17 — Pricing & billing plumbing (per MVP §"Pricing", line 805)
Pricing curve must be decided before Stage 3 ships (MVP line 805–806). Capture the decision in docs/pricing-stage-3.md.
Implement metering (counts of enforcement events, audit-record retention days, kill-switch invocations) in the gateway and surface it in the admin API. Billing integration itself can wait if a hand-invoiced design partner is the first paying team.
Task 18 — Reference materials & migration guide
docs/migrating-from-local.md: the before/after, the cryptographic story (why the API key is not a token), the data that does and does not leave the customer's network in hosted mode (be explicit — this is the SOC2/GDPR question the gate awaits).
Update README.md and public/packages/mcp/README.md with the hosted option, keeping local-first messaging intact.
Phase G — Verification before declaring Stage 3 shipped
Task 19 — Cross-stage parity test suite
A test harness that runs the same AgentCapabilityManifest through (a) @euno/mcp local mode and (b) the hosted gateway, against a recorded set of tools/call requests, and asserts: identical decisions, identical OCSF record contents pre-signature, identical obligations applied. This is the operational proof of the parity claim in MVP §"Policy and audit schema parity".
Lives in euno-platform/packages/integration-tests/ (existing package).
Task 20 — Gate-to-Stage-4 instrumentation
Confirm the Stage 4 gate (MVP lines 693–696): ≥1 paying team and a written security/compliance question. Wire scripts/stage4-readiness.ts (Task 16) to report green; do not begin Stage 4 work until it does.
Cross-cutting obligations (apply to every task above)
Schema parity is non-negotiable (MVP lines 507–554). Any change to policy or audit shape must land in @euno/common-core first, with a parity test added in the same PR.
No Stage-3-only types in @euno/mcp or tool-gateway that aren't also in @euno/common-core (Critical Risks, MVP lines 871–874).
Fail-closed defaults for hosted mode: unknown condition → deny; KMS unavailable → deny; Redis unavailable for counters → deny (operator-overridable for self-host).
Each task ships with: unit tests, an integration test exercising the new wire path, a README/section update, and a CHANGELOG entry under the @euno/mcp 0.3.0 and tool-gateway 1.0.0 headings.
Status tracking format: mirror Stage 1 and Stage 2 — add a > **Stage 3 status** block to docs/mvp.md with one bullet per Task 0–20 and check them off as they land.
Suggested sequencing (dependency order)
Tasks 0, 1 (parallel; both blocking).
Tasks 3, 4, 5, 6 (parallel — pure seam swaps inside the existing gateway code).
Tasks 7, 8, 9 (parallel after step 2).
Task 2 (after step 3 — the client needs the protocol from Task 9).
Tasks 10, 11, 12 (sequential within the minter; gated by Task 1 sign-off).
Tasks 13, 14 (parallel after steps 2–4).
Tasks 15, 16, 17, 18 (parallel after step 5).
Tasks 19, 20 (final).
Stage-3-shipped definition
All of the following are simultaneously true:

Tasks 0–20 are checked off in docs/mvp.md.
Parity test suite (Task 19) is green in CI.
Threat model (Task 1) is signed off and the minter's monitoring rules (Task 12) are firing on a test tenant.
A real customer can perform the single config change (Task 15) and route enforcement through the hosted gateway end-to-end with KMS-signed audit reaching their query API.
scripts/stage4-readiness.ts (Task 20) reports both Stage 4 gate signals as met.
