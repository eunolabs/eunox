Stage 2 Execution Plan — @euno/mcp General Tool Enforcement

> **Status (May 2026): All 12 tasks are COMPLETE.**
> `@euno/mcp` 0.1.0 ships all Stage-2 condition types, CLI subcommands,
> reference policies, the `@euno/langchain` companion package, and full
> documentation coverage. See docs/mvp.md §"Stage 2 status" for the
> authoritative per-task checklist.

This plan turns docs/mvp.md §"Stage 2: General Tool Enforcement" (lines 552–574) into a numbered task list modeled on the Stage 1 task structure (mvp.md lines 313–328). Each task is sized so it can be assigned to Copilot as a single issue, includes the file-level scope, the rationale grounded in already-shipped code, and an explicit acceptance criterion. A note on prerequisites and shared context for every task is at the top so issues can be created with that block prepended.



Shared context (paste into every Stage 2 issue)


Repository layout. Public, Apache-2.0 packages live under public/packages/{cli,common,mcp,langchain}. The `@euno/common-core` package lives at `pkg//` (the directory was renamed from `common-core` to `common`; the npm package name `@euno/common-core` is unchanged). Stage 2 work stays inside pkg/ plus pkg/ and pkg//policies/. Do not add Redis, Postgres, KMS, or any cross-process state — that is Stage 3.

Reuse, do not reinvent. All five Stage-2 condition types already exist in pkg//src/condition-registry.ts: ipRangeHandler, recipientDomainHandler, redactFieldsHandler, policyHandler, plus the registerCustomCondition / registerPolicyBackend registries. enforceCondition and the two-tier ordering helpers in the same file already handle them. Stage 2 is mostly lifting the Stage-1 gate, wiring richer request context, and surfacing the new capabilities through the CLI/policy/audit surfaces — no new condition logic in @euno/common-core.

Stage-1 gate to lift. pkg//src/policy/source.ts defines DEFERRED_CONDITION_TYPES (lines 50–56) and rejectDeferredConditions (lines 66–94), and rejects ipRange | recipientDomain | redactFields | policy | custom. Stage 2 removes types from this set as the matching wiring lands — never lift the gate before the wiring is in place, because the existing gate fails fast with a clear error and partial wiring would silently degrade enforcement.

PDP entry point. pkg//src/pdp.ts. The shape ConditionContext from @euno/common-core/condition-registry (lines 50–102) is the integration seam — populating sourceIp, recipients, customHandlers, policyBackends is how the new condition types start getting real values. The conditionTypeToDenialCode map already includes ipRange and recipientDomain (lines 241–253) — extend it as needed.

Audit shape. pkg//src/audit/audit-sink.ts writes OCSF API Activity events (class_uid 6003) with a unmapped field that already includes denialCode and conditionType (lines 267–268). New denial-cause fields (e.g. for argument-schema details) go in unmapped. The LocalHmacSigner round-trip is already validated by verifyAuditEvent.

Schema parity is non-negotiable. Per mvp.md §"Policy and audit schema parity" (lines 501–548): the policy file is a literal subset of AgentCapabilityManifest; @euno/mcp imports types from @euno/common-core and never defines its own. Unknown condition types are denied at validate time and at enforcement time (defence in depth). Stage 2 must not relax this.

Build and check commands (verified): from repo root, npm install, then npm run lint, npm run test, npm run build. The MCP package alone: npm run -w @euno/mcp test. Build order is in package.json:10 — common-core → common-infra → common → posture-emitter → @euno/mcp → other workspaces.

Distribution. @euno/mcp is published via .github/workflows/release-mcp.yml to GitHub Packages (publishConfig.registry). New @euno/langchain package follows the identical publish workflow with its own release file.

Telemetry. denialsByConditionType is already collected in pkg//src/telemetry/collector.ts. New denial codes added in Stage 2 land in that map automatically. Do not add identifying fields — see TELEMETRY.md.

Stage 2 readiness gate. Do not start Stage 2 work until scripts/stage2-readiness.ts reports READY, or a maintainer has explicitly acknowledged the gate criteria are met. Each of the tasks below is independent of that gate decision.



Stage 2 status block (to be added to mvp.md when work begins)


Stage 2 status (target: …)



 Task 1 — argumentSchema structured error reporting

 Task 2 — ipRange condition: lift gate, wire sourceIp from HTTP transport

 Task 3 — recipientDomain condition: lift gate, extract recipients from tool args

 Task 4 — redactFields condition: lift gate, response-path obligation in proxy

 Task 5 — policy condition: lift gate, policy-backend module loader

 Task 6 — custom condition: lift gate, custom-handler module loader

 Task 7 — euno-mcp validate-token CLI (audit log explainer)

 Task 8 — euno-mcp stats CLI (denial-reason histograms from local audit log)

 Task 9 — @euno/langchain companion package — wrapAsLangChainTool over local-only CapabilityRuntime

 Task 10 — Reference policy library under pkg//policies/

 Task 11 — README + docs updates: condition matrix, before/after, schema-parity claim

 Task 12 — Stage 3 readiness script + signal collection update




Task 1 — argumentSchema structured error reporting

Why. mvp.md line 562: "argument-schema validation with structured error reporting". Today pdp.ts (lines 511–524) catches the validator error and returns only a string reason. MCP clients have no machine-readable way to react.


Scope.



File: pkg//src/pdp.ts — extend PdpDecision with an optional details?: Record<string, unknown> field (already an obvious extension shape, alongside denialCode/conditionType). When the validateArguments call throws, capture the structured information the validator already exposes (path, expected, got) and put it on details.

Verify the validator surface: pkg//src/argument-validator.ts — confirm the error class exposes path / expected / actual. If only a string is exposed today, first add a typed ArgumentValidationError (with path, expected, got) to @euno/common-core and re-export from @euno/common. Do not break existing tests — keep the .message shape compatible.

File: pkg//src/transport/stdio.ts and transport/http.ts — the place that turns a PdpDecision into the JSON-RPC error response must serialise details into the data field of the JSON-RPC error object (the SDK supports it). Match the shape { code: 'ARGUMENT_VALIDATION_FAILED', conditionType: 'argumentSchema', details: { path, expected, got } }.

File: pkg//src/audit/audit-sink.ts — extend McpAuditRecord with optional details?: Record<string, unknown> and write it into the existing unmapped block alongside denialCode/conditionType. Do not put it at the top level of the OCSF event — unmapped is the documented escape hatch (lines 25–28 of audit-sink.ts).


Acceptance.



New unit tests in pkg//src/__tests__/ covering: a denied call returns a structured details object; the audit log captures the same details; the existing tests continue to pass.

One end-to-end test using the mock upstream from test/fixtures/ proves a client receives the structured error.

No change to allow-path behaviour.



Task 2 — ipRange condition: lift gate, wire sourceIp from HTTP transport

Why. mvp.md line 562: "IP allowlists". The handler already exists in condition-registry.ts (lines 502–516) and already understands ctx.sourceIp. Stage 1 ships the deny path (no sourceIp → "ipRange requires sourceIp in request context").


Scope.



File: pkg//src/transport/http.ts — at the request handler, capture the source IP. Honour X-Forwarded-For only when the proxy is bound to loopback (the default) and the operator has explicitly opted in via a new --trust-forwarded-for CLI flag (default off). Otherwise use req.socket.remoteAddress. Strip the ::ffff: IPv4-mapped prefix the same way _handleControlKill does today (http.ts lines 683–687).

File: pkg//src/pdp.ts — extend PdpContext with sourceIp?: string. Pass it through into ConditionContext in decide() (around line 531).

File: pkg//src/transport/stdio.ts — leave sourceIp undefined for stdio sessions (the existing handler will deny if a policy includes ipRange, with a clear reason). Document this in the README ("ipRange is enforced only over HTTP transport").

File: pkg//src/policy/source.ts — remove 'ipRange' from DEFERRED_CONDITION_TYPES (line 50 set). Add a new test that loads a policy containing ipRange and asserts it succeeds.

File: pkg//src/cli.ts — add the --trust-forwarded-for flag to the proxy subcommand with a stderr warning at startup when enabled.


Acceptance.



Unit tests in pdp.test.ts covering allow / deny based on CIDR list and the no-IP case.

Integration test in test/transport-http.test.ts that fires a request from 127.0.0.1, denies a request whose X-Forwarded-For says 198.51.100.1 when the flag is off, and allows it when the flag is on and the policy lists that CIDR.

The new denialsByConditionType bucket increments correctly (telemetry/collector.ts).



Task 3 — recipientDomain condition: lift gate, extract recipients from tool args

Why. mvp.md line 562 (implied by the full union). Handler in condition-registry.ts lines 652–687 already matches against a list of bare domains and reads ctx.recipients.


Scope.



File: pkg//src/pdp.ts — add an extractRecipients(rawArgs) helper alongside extractFilePath/extractTables/extractSqlOperation (around lines 200–230 of pdp.ts; verify their helpers). Recognise the common shapes tool authors use: to, recipients, cc, bcc — strings or arrays of strings. Return string[] | undefined.

Wire the extracted value into ConditionContext in decide() (around line 539).

File: pkg//src/policy/source.ts — remove 'recipientDomain' from DEFERRED_CONDITION_TYPES.

Update the denial-code map in pdp.ts (already includes recipientDomain → RECIPIENT_DOMAIN_DENIED, line 250 — confirm and reuse).


Acceptance.



Unit tests over each shape (to: string, to: string[], cc + bcc, missing → undefined).

Policy-loader test confirms recipientDomain is now accepted.

Integration test denies a tools/call with to: ["evil@attacker.example"] against an allowlist of [example.com].



Task 4 — redactFields condition: lift gate, response-path obligation in proxy

Why. mvp.md line 562 (richer conditions). redactFieldsHandler (condition-registry.ts lines 689–707) is a response-path obligation — enforce() always allows; the work happens in redact(). Today the proxy never invokes the response-path lobe because Stage 1 only intercepts the request path.


Scope.



Files: pkg//src/transport/stdio.ts and transport/http.ts — after the upstream returns a tools/call result, if the matched constraint had redactFields conditions, walk the result through the registry's response-path helpers. The registry already exposes redactConditions and hasRedactObligation (condition-registry.ts lines 795 and 843) — use these directly; do not reimplement the dotted-path stripping (deleteDottedPath).

File: pkg//src/pdp.ts — decide() returns the matched constraint via the existing path. Extend PdpDecision with an optional obligations?: { redactFields?: string[][] } (or surface the matched conditions list via a new decideWithObligations helper, whichever is cleaner — the simpler path is to return the matched CapabilityConstraint reference inside the decision so the transport can run obligations without re-doing the match).

File: pkg//src/policy/source.ts — remove 'redactFields' from DEFERRED_CONDITION_TYPES.

File: pkg//src/audit/audit-sink.ts — record obligationsApplied: ['redactFields'] in unmapped so operators can see the response was rewritten.


Acceptance.



Unit tests demonstrating fields are stripped from result.content[0].text when JSON, and from result.structuredContent when present.

Test that redactFields does not alter the response when the response is non-JSON text (no silent JSON parsing).

Audit record includes obligationsApplied.



Task 5 — policy condition: lift gate, policy-backend module loader

Why. mvp.md line 562 plus the wider Stage 2 union. policyHandler (lines 709–734 of condition-registry.ts) delegates to backends registered via registerPolicyBackend. Stage 1 has no way for an operator to register one.


Scope.



File: pkg//src/cli.ts — add a new --policy-backend <module> repeatable flag on the proxy subcommand. Each value is a Node module path (relative or absolute) that exports a default function (api: { registerPolicyBackend }) => void. Resolve modules with the same rules import() uses (CommonJS / ESM both).

File: pkg//src/policy/backends.ts (new) — small loader that imports each module, calls its default export with { registerPolicyBackend } from @euno/common-core, and emits structured stderr logs ([euno-mcp] registered policy backend: <name>).

File: pkg//src/policy/source.ts — remove 'policy' from DEFERRED_CONDITION_TYPES.

Document the SDK contract for backend authors in a new pkg//docs/policy-backends.md (1–2 pages, matching the tone of TELEMETRY.md). Worked example: an OPA-style allow/deny.

README update: add a "Custom policy backends" section.


Acceptance.



Integration test that loads a fixture backend module from test/fixtures/policy-backends/echo-deny.ts, registers it, and confirms a policy condition referencing that backend denies as expected.

Loader propagates module errors with a clear stderr line and exits non-zero before the proxy starts.

The Stage-3 swap path remains intact: backends register against the shared @euno/common-core registry, so a Stage-3 hosted gateway picks up the same module unchanged.



Task 6 — custom condition: lift gate, custom-handler module loader

Why. Same family as Task 5; registerCustomCondition already exists (condition-registry.ts line 202). The condition-registry already validates that custom handlers are registered.


Scope.



File: pkg//src/cli.ts — add --custom-condition <module> repeatable flag on the proxy subcommand, mirroring Task 5's --policy-backend.

File: pkg//src/policy/custom-handlers.ts (new) — loader analogous to Task 5; calls each module's default export with { registerCustomCondition }.

File: pkg//src/policy/source.ts — remove 'custom' from DEFERRED_CONDITION_TYPES.

File: pkg//src/pdp.ts — populate ConditionContext.customHandlers from getCustomConditionHandlers() so the registered handlers are actually visible during enforcement (around line 539).

New pkg//docs/custom-conditions.md with worked example.


Acceptance.



Integration test loading a fixture handler that denies based on a synthetic field on arguments.

Loader errors fail fast with clear messages (file not found, default export wrong shape).

Validation-time check: a manifest referencing a custom condition whose handler is not registered is rejected at proxy startup with a pointer to the --custom-condition flag.



Task 7 — euno-mcp validate-token CLI (audit log explainer)

Why. mvp.md line 563: "euno-mcp validate-token CLI for inspecting why a request was denied (reads the local audit log, reconstructs the decision)". Despite the name, this is not a JWT verifier in Stage 2 — token-based enforcement is Stage 3. The Stage-2 deliverable is an audit-log inspector that explains a single decision.


Scope.



File: pkg//src/cli.ts — register a new subcommand:

euno-mcp validate-token --request-id <uid> — finds the matching audit record by metadata.uid and prints a human-readable summary (decision, denialCode, conditionType, details, signing key fingerprint, signature verification result via the existing verifyAuditEvent).

euno-mcp validate-token --since <ISO8601> — prints a one-line-per-decision tail of recent records.

--audit-log <path> (default ~/.euno/audit.jsonl) — same default as the proxy.



File: pkg//src/audit/audit-sink.ts — confirm verifyAuditEvent (line 437) is exported and stable. If not, expose it through audit/index.ts.

File: pkg//src/cli/validate-token.ts (new) — the implementation. Output format mirrors the euno-mcp validate pattern (✓/✗ + indented details).

Telemetry: emit a new subcommand: 'validate-token' event so the existing collector counts these invocations. Update TelemetryEvent.subcommand type union (telemetry/types.ts line 35).


Acceptance.



Unit tests over a fixture audit file with allow + deny entries; both lookups produce the expected output.

HMAC tampering is reported as a verification failure, not a parse error.

Exit codes: 0 = found and verified; 1 = not found; 2 = found but signature invalid.



Task 8 — euno-mcp stats CLI (denial-reason histograms from local audit log)

Why. mvp.md line 566: "expose denial-reason histograms in the local CLI (euno-mcp stats)".


Scope.



File: pkg//src/cli/stats.ts (new). Command: euno-mcp stats [--since <ISO8601>] [--audit-log <path>]. Reads the JSONL audit log, aggregates by unmapped.conditionType and unmapped.denialCode, and prints a small ASCII table:
Code
Period: 2026-05-08 → 2026-05-15  (Total: 1,237 calls; 89 denied)
─────────────────────────────────────────────────────────────────
 conditionType        denialCode                  count    %
 maxCalls             MAX_CALLS_EXCEEDED            42  47%
 argumentSchema       ARGUMENT_VALIDATION_FAILED    21  24%
 …


Reuse the OCSF parsing already implicit in the verify path. Skip records that fail to parse; emit a stderr summary count.

Honour the existing audit log rotation (read all .jsonl plus archived files under ~/.euno/) — confirm rotation naming convention from audit-sink.ts and reuse it.

Wire telemetry as a new subcommand: 'stats' event.


Acceptance.



Unit tests over fixture audit files with mixed allow/deny mixes.

Stable column ordering and totals; deterministic on the same input.

--since filters precisely on time field.



Task 9 — @euno/langchain companion package

Why. mvp.md line 564: "@euno/langchain companion package — wraps a Tool / StructuredTool so LangChain.js users who don't want to introduce an MCP transport into a Node process can adopt euno in-process. Uses the same AgentCapabilityManifest and the same enforcement core. Not a separate enforcer — the same CapabilityRuntime shape used by internal/agent-runtime, just with a local-only backend."


Scope.



New package pkg// published as @euno/langchain (Apache-2.0). Mirror the structure of pkg//: package.json, tsconfig.json, jest.config.js, README.md, LICENSE, src/, test/. The publish workflow is a copy of release-mcp.yml named release-langchain.yml.

Reuse — do not depend on internal/framework-adapters (that is a private/BSL workspace). Re-implement the structural LangChainCompatibleTool shape from internal/framework-adapters/src/langchain.ts lines 44–59 inside this package, but route enforcement through @euno/mcp's ConditionEnforcerPDP (or factor a thin shared helper into @euno/mcp if needed). The agent-runtime CapabilityRuntime interface is what the structural type should match — copy only the public, structural pieces, keeping the implementation Apache-2.0-clean.

Public API:
ts
import { wrapAsLangChainTool, EunoLangChainCallbackHandler, createLocalRuntime } from '@euno/langchain';

const runtime = await createLocalRuntime({
  policyFile: './euno.policy.yaml',
  auditLog: '~/.euno/audit.jsonl',
});

const tool = wrapAsLangChainTool(runtime, {
  name: 'query_db',
  description: '…',
  schema: { type: 'object', properties: { query: { type: 'string' } } },
});


The local runtime composes FilePolicySource + ConditionEnforcerPDP + LocalAuditSink from @euno/mcp — no Redis, no signing service. Same denial codes, same audit shape.

Tests: structural compatibility against @langchain/core's StructuredTool (use the structural-typing pattern from internal/framework-adapters/tests/langchain.test.ts so we don't add @langchain/core as a runtime dep).

Dependencies — verify Apache-2.0 / MIT compatibility before adding (gh-advisory-database for any new npm dep). The only new runtime dep should be @euno/mcp itself (or, alternatively, @euno/common-core + the new shared helper described above).

License lint: extend scripts/check-license-boundary.mjs to allow @euno/langchain in the public Apache-2.0 set.


Acceptance.



npm run -w @euno/langchain test green.

README before/after snippet showing a LangChain tool blocked from a destructive SQL call.

The euno.policy.yaml accepted by @euno/mcp is accepted byte-for-byte by @euno/langchain.

Repo-root npm run lint && npm run test && npm run build green.



Task 10 — Reference policy library

Why. mvp.md line 565: "3–5 pre-baked euno.policy.yaml files for common upstream MCP servers (filesystem, Postgres, GitHub, Slack), in a pkg//policies/ directory. This is what makes the 5-minute pitch real."


Scope.



New directory pkg//policies/ with at least the following files (pick five from the list in mvp.md):

filesystem.policy.yaml — for @modelcontextprotocol/server-filesystem. Use allowedExtensions and per-tool argumentSchema to block writes outside a directory whitelist.

postgres.policy.yaml — for the canonical Postgres MCP server. Use allowedOperations: ['SELECT'] plus allowedTables per tenant guidance.

github.policy.yaml — read-only by default, write tools gated by maxCalls.

slack.policy.yaml — recipientDomain allowlist for messaging tools.

fetch.policy.yaml — ipRange allowlist (deny private CIDRs from being targets) using argumentSchema to extract the URL.



Each file must validate cleanly via euno-mcp validate <file> — add a CI job in .github/workflows/ (or a new test in pkg//test/) that loops over the directory and asserts each policy validates.

Each file must include a top-of-file comment block: upstream package + version it targets, what the policy blocks, what it deliberately leaves open, and a link back to its README.

Update pkg//README.md with a "Reference policies" section that lists each one with a one-line description.


Acceptance.



New CI step (or new test in policies.test.ts) loads every *.policy.yaml under pkg//policies/ and asserts the loader returns a valid manifest.

One end-to-end test per policy proving at least one obvious denial (e.g., for postgres.policy.yaml, a DROP TABLE is denied; for fetch.policy.yaml, http://169.254.169.254/... is denied).

The pitch.md / launch-post.md is updated with a link to the directory.



Task 11 — README + docs updates: condition matrix, before/after, schema-parity claim

Why. Stage 1 README copy says "v0 supports a strict subset" — Stage 2 expands the matrix. The "fail-fast on unknown condition types" claim must continue to hold post-Stage-2.


Scope.



Files: pkg//README.md and pkg//docs/. Update the supported-conditions matrix to mark ipRange, recipientDomain, redactFields, policy, custom as supported. Add a footnote linking to the policy/custom backend docs (Tasks 5/6).

Add the second worked example: a request denied by recipientDomain over the HTTP transport.

Update the "What is explicitly cut from Stage 1" section so any reader cross-referencing mvp.md sees the Stage 2 deltas.

Update pkg//CHANGELOG.md with a Stage-2 release entry that names every new flag, every new subcommand, and every new condition.

Update docs/mvp.md Stage-2 status block with the same checklist used at the top of this plan.


Acceptance.



npm run lint (markdown lint included if configured) green.

A grep over README confirms no Stage-1 sentence still says condition X is "deferred".



Task 12 — Stage 3 readiness script + signal collection update

Why. mvp.md lines 568–573 set the gate to Stage 3 — three measurable signals. We follow the Stage-1 pattern of shipping the readiness script alongside the work.


Scope.



New file scripts/stage3-readiness.ts modeled on scripts/stage2-readiness.ts (which already exists and is the correct template). Three criteria:

C1: ≥5 teams (≥3 users each) confirmed running it (telemetry + at least one direct conversation per team).

C2: ≥3 unsolicited "share policy across team" or "see what the agent did from my laptop" asks.

C3: ≥1 conversation with a team that has already implemented some hand-rolled cross-process audit.



Telemetry collector update (pkg//src/telemetry/collector.ts) — add (privacy-preserving) per-install team-size estimate inferred only from installId + ephemeral counts. Do not add IPs, hostnames, or user identifiers — that is non-negotiable. If a privacy-preserving estimate isn't possible, leave C1 manually tracked and document that.

New .github/ISSUE_TEMPLATE/stage-3-signal.md modeled on .github/ISSUE_TEMPLATE/feature-ask.md (referenced in stage2-readiness.ts line 129).

Cross-link the script in docs/mvp.md Stage 3 gate paragraph.


Acceptance.



npx ts-node scripts/stage3-readiness.ts runs and prints the three criteria with UNKNOWN status when no telemetry endpoint is configured (mirrors the Stage-2 script).

Exit codes match the Stage-2 script convention: 0 ready, 1 not met, 2 unknown.



Cross-cutting acceptance for the whole stage


No new cross-process state. No Redis, no Postgres, no KMS, no network-resident signing. Anything in that direction is Stage 3.

Schema parity holds. Every new condition lifted in Tasks 2–6 is validated through validateManifest from @euno/common-core. @euno/mcp defines no new condition or constraint types.

Defence-in-depth invariant preserved. Unknown condition types are still denied at enforcement time even when they slip past the loader. Verify by removing the loader-time gate for one type and asserting the enforcement path still denies — keep this as a unit test.

Telemetry stays opt-in. Default off; counts only; EUNO_TELEMETRY=0 disables. New denial buckets land in denialsByConditionType automatically.

Drop-in upgrade for Stage-1 users. A user on @euno/mcp@0.1.x whose policy file uses only Stage-1 conditions sees no behavioural change after upgrading to the Stage-2 release. Add a 0.1.x → 0.2.x upgrade note in CHANGELOG.md.

Repository-wide checks. npm run lint && npm run test && npm run build from the repo root must be green at the close of every task.



Suggested sequencing for Copilot assignment


Tasks 1, 2, 3 in parallel — independent surface changes, all touch pdp.ts differently and policy/source.ts for one entry each. Land in the listed order to minimise rebases.

Tasks 4, 5, 6 after 1–3 — they each modify the CLI plumbing or the response path, but don't conflict with each other (different files / different gate-list entries).

Tasks 7 and 8 in parallel after Task 1 — both depend on the structured details shape Task 1 introduces.

Task 9 (@euno/langchain) is independent of 1–8 and can run in parallel from day one; it depends only on the existing @euno/mcp 0.1.x surface plus the Apache-2.0-clean re-implementation of the LangChain wrapper.

Tasks 10, 11, 12 last — they capture the final surface for the user, the docs, and the next gate.
