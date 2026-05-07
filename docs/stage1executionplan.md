Stage 1 Execution Plan — @euno/mcp MCP Proxy MVP
This plan decomposes Stage 1 of docs/mvp.md (lines 276–445) into 15 Copilot-assignable tasks, grouped by the three two-week phases the doc specifies. Each task is written to be self-contained: one engineer (or one Copilot session) should be able to execute it with only the linked files and the task body.

Global context every task must know

Stage 1 ships a single new package: packages/euno-mcp (publishes as @euno/mcp), Apache-2.0.
The package is a proxy MCP server: stdio (primary) and streamable HTTP (secondary). It forwards tools/list / resources/list / prompts/list, intercepts tools/call, enforces a local policy, and either forwards or returns a structured denial.
Schema parity is non-negotiable (docs/mvp.md §"Policy and audit schema parity"): @euno/mcp MUST import AgentCapabilityManifest, CapabilityConstraint, CapabilityCondition, ArgumentSchema from @euno/common-core (packages/common-core/src/wire.ts:594). It MUST NOT define new policy types. Unknown condition types MUST be rejected at validate time and at proxy startup, and denied at enforcement time.
The four interface seams used by Stage 3 already exist in @euno/common-core. Stage 1 wires the in-memory implementations of each:
TokenVerifier → not used in Stage 1 (no JWT); instead a small new LocalPolicySource interface lives in @euno/mcp so Stage 3's signed-JWT loader is a drop-in replacement.
CallCounterStore → InMemoryCallCounterStore from packages/common-core/src/call-counter-store.ts.
EvidenceSigner → local HMAC implementation new to @euno/mcp (key in ~/.euno/key).
KillSwitchManager → in-memory backend from packages/common-core/src/kill-switch.ts.
The CapabilityCondition variants supported in v0 are exactly: maxCalls, timeWindow, allowedOperations, allowedExtensions, allowedTables, plus the argumentSchema field on CapabilityConstraint. ipRange, recipientDomain, redactFields, policy, custom are deferred to Stage 2 — and must therefore be rejected, not silently accepted.
Session identity (mvp.md §"Session identity"): a session is one MCP client connection. Counter keys are <sessionId>|<toolName>|<resource>. For stdio the session is the lifetime of the proxy process; for HTTP it is one MCP initialize → shutdown cycle keyed by clientInfo + a server-minted session id.
Reuse, don't reimplement: condition-registry, argument-validator, capability-validators, InMemoryCallCounterStore, in-memory KillSwitchManager, the euno validate codepath in packages/cli.
Audit log: jsonl, OCSF-shaped (use @euno/common-core/src/ocsf.ts), HMAC-signed locally. Format must be byte-for-byte identical in shape to what the Stage 3 gateway writes — the only thing that changes is the signer.
License direction rule: @euno/mcp is Apache-2.0 and may only depend on Apache-2.0 packages (common-core, cli). It must not import from common-infra, tool-gateway, capability-issuer, etc. The existing CI lint that walks the workspace dependency graph will fail the build otherwise.
Repo state already done by Stage 0 (verified): common-core / common-infra split exists; this plan does not redo Stage 0 work.
Out of scope for Stage 1 (mvp.md §"What is explicitly cut from Stage 1"): token issuance, KMS / cloud, DID / federation / cross-chain anchor, Redis / Postgres / multi-process, MAF / CrewAI adapters, the posture-emitter / db-token-service / storage-grant-service / partner-issuer-sim packages, multi-cloud IdPs, sandboxing guidance.

Phase A — Weeks 1–2: Skeleton + Transport
Task 1. Scaffold packages/euno-mcp
Goal. Create the new package with the right license, manifest, build wiring, and dependency direction. No proxy logic yet.

Scope.

Create packages/euno-mcp/ with package.json (name @euno/mcp, license Apache-2.0, bin: { "euno-mcp": "./dist/cli.js" }), tsconfig.json extending the root config, src/index.ts, src/cli.ts, README.md (placeholder), LICENSE (Apache-2.0).
Add @modelcontextprotocol/sdk as a direct dep, pinned to a single revision (no ^/~); record the version + reasoning in docs/mcp-support.md if not already present.
dependencies: only @euno/common-core, @modelcontextprotocol/sdk, commander (or whatever the existing cli package uses — check first), zod (for policy parsing if common-core doesn't already export validators).
Add the package to the root build chain after common-core and before cli (root package.json:9-12, see memory: build order).
Wire root npm run lint, npm run test, npm run build to pick the new workspace up automatically (workspace globs).
Acceptance.

npm run build from repo root succeeds.
npm run lint and npm run test pass (no tests yet — empty __tests__ is fine).
The Apache→BSL dependency-graph CI lint passes.
npx -y @euno/mcp --help (after a local npm pack) prints the binary's help.
References. mvp.md §"License boundary", §"Stage 1 / What ships". Memory: "Root build order".

Task 2. Pin and document the MCP SDK support window
Goal. Make MCP-version drift a deliberate, versioned decision before any proxy code lands.

Scope.

Create or update docs/mcp-support.md recording: pinned @modelcontextprotocol/sdk version, the MCP protocol revision string, the support window (e.g. "current minor + 1 prior minor"), and the upgrade procedure.
Add a MCP_PROTOCOL_VERSION constant exported from packages/euno-mcp/src/protocol.ts and assert it in the proxy's initialize handshake (later tasks will use this).
Acceptance. Doc exists, constant is exported, and is referenced in the README's compatibility section once Task 14 lands.

References. mvp.md §"Stage 0" bullet on pinning the MCP SDK; §"Weeks 5–6" reiterates the pin.

Task 3. Stdio transport with full passthrough + tools/call interception
Goal. A stdio proxy that spawns an upstream MCP server as a child, pipes JSON-RPC frames through, forwards tools/list / resources/list / prompts/list verbatim, and intercepts tools/call for later policy enforcement (denial path returns a stub CapabilityDenied for now — real enforcement lands in Phase B).

Scope.

packages/euno-mcp/src/transport/stdio.ts: spawn upstream via child_process.spawn with the user-supplied command + args; bidirectionally pipe stdin/stdout. Use @modelcontextprotocol/sdk's server + client constructs — do not hand-roll JSON-RPC framing.
Forward all method calls except tools/call verbatim.
Intercept tools/call: call a PolicyDecisionPoint interface (defined as { decide(req): { allow: boolean; reason?: string; denialCode?: string } } in src/pdp.ts). For now ship a AlwaysAllowPDP so the transport can be tested end-to-end.
Propagate stderr from the upstream so debugging is not silently lost.
Handle SIGINT / SIGTERM: forward to child, wait up to N seconds, then kill.
Acceptance.

New integration test (Task 4) passes with this transport against a 30-line mock stdio echo server.
Manual: dropping the proxy in claude_desktop_config.json in front of @modelcontextprotocol/server-filesystem works for tools/list and tools/call.
Dependencies. Task 1.

References. mvp.md §"What ships / stdio (primary)"; §"Weeks 1–2".

Task 4. Mock upstream MCP server + stdio integration test
Goal. Establish a hermetic test fixture used by every later task that needs an upstream.

Scope.

packages/euno-mcp/test/fixtures/mock-upstream.ts: ~30-line stdio MCP server exposing two tools (echo, query_db) and one resource. Built into dist so it can be spawned as a binary from tests.
packages/euno-mcp/test/transport-stdio.test.ts: spawns the proxy with the mock upstream as its child, sends tools/list and tools/call over stdio, asserts response shape.
Use the existing repo test runner (Jest — see root package.json).
Acceptance. npm test --workspace @euno/mcp passes deterministically (no flake on CI).

Dependencies. Task 3.

References. mvp.md §"Lightweight integration test using a mock upstream MCP server".

Task 5. Streamable HTTP transport
Goal. The "secondary" transport for LangChain.js / in-process clients / Show HN demos. Same enforcement boundary as stdio.

Scope.

packages/euno-mcp/src/transport/http.ts: implement the streamable HTTP transport per the MCP spec, using @modelcontextprotocol/sdk primitives. Bind to 127.0.0.1 by default; must explicitly refuse 0.0.0.0 unless an --unsafe-bind-all flag is passed (and even then, log a one-line warning at startup).
Session model: one MCP initialize → shutdown cycle = one session. Mint a session id; key it with clientInfo from initialize (mvp.md §"Session identity"). Document the keying in code comments referencing the production IssuanceRateLimitSubject shape (see memory: rate limiting; packages/common-core/src/issuance-rate-limiter.ts:107-128).
tools/call interception path identical to stdio: hits the same PolicyDecisionPoint.
Concurrent sessions are isolated: counter keys (Task 8) include sessionId.
Acceptance.

Integration test analogous to Task 4 but over HTTP.
Trying --transport http --bind 0.0.0.0 without --unsafe-bind-all exits non-zero with a clear error.
Dependencies. Task 3 (shares PDP interface), Task 4 (reuses fixture).

References. mvp.md §"streamable HTTP (secondary)".

Task 6. Local OCSF audit log with HMAC signer
Goal. Every enforcement decision is durably recorded in a format identical in shape to the Stage 3 gateway's signed evidence stream — only the signer differs.

Scope.

packages/euno-mcp/src/audit/: build an EvidenceSigner implementation that signs OCSF records with HMAC-SHA-256 over the canonicalised payload. Key generated on first run with crypto.randomBytes(32), written to ~/.euno/key with mode 0600. If the key file exists and is unreadable, fail-fast.
Audit sink writes JSON Lines to ~/.euno/audit.jsonl (configurable via --audit-log and the programmatic auditLog option). Append-only; rotate at a configurable size (default 100 MiB) to audit.jsonl.<timestamp>.
Use the OCSF type / helper already in packages/common-core/src/ocsf.ts so the record shape is identical to gateway output.
Each record carries: session id, tool name, resource (where applicable), decision (allow | deny), denial code, condition type that caused denial, monotonic counter, signer kid (e.g. local-hmac-v1), HMAC tag.
Acceptance.

Unit test verifies the OCSF record schema-matches a fixture from the gateway side (copy a small fixture from packages/tool-gateway or the issuer if one exists; otherwise round-trip through the common-core OCSF type).
Unit test verifies HMAC verification round-trips.
File mode on the key file is 0600 on POSIX.
Dependencies. Task 1.

References. mvp.md §"Local jsonl audit log (~/.euno/audit.jsonl), OCSF-shaped, locally HMAC-signed". Schema-parity table at lines 461-468.

Phase B — Weeks 3–4: Policy Engine + CLI
Task 7. LocalPolicySource + YAML/JSON loader producing AgentCapabilityManifest
Goal. Establish the only seam that is genuinely new in Stage 3 (mvp.md line 478-483): the policy source. In Stage 1 it loads a local file; in Stage 3 it will be replaced by a JWT loader without changing the consumer.

Scope.

packages/euno-mcp/src/policy/source.ts:
ts
export interface LocalPolicySource {
  load(): Promise<AgentCapabilityManifest>;
  watch?(onChange: (m: AgentCapabilityManifest) => void): () => void; // optional file-watch
}
FilePolicySource implementation accepting .yaml/.yml/.json. Use an existing YAML lib already in the repo (check root package.json first; do not add a new one if avoidable).
The loader MUST validate the loaded object against AgentCapabilityManifest from @euno/common-core (packages/common-core/src/wire.ts:594). If common-core already exports a Zod or runtime validator, use it; otherwise add one in common-core (separate Task 7a) and import it.
Reject unknown CapabilityCondition type values, unknown top-level fields, and any of the deferred condition types (ipRange, recipientDomain, redactFields, policy, custom) with clear error messages naming the offending JSON path.
Reject manifests that use schema features not yet supported (return the same fail-fast error the production gateway would).
Acceptance.

Unit tests for: happy YAML, happy JSON, unknown condition type → reject, deferred condition type → reject (with explicit error mentioning Stage 2), schema-valid but semantically broken (e.g. notAfter before notBefore) → reject.
The error message format is consistent with the production euno validate so users get the same UX (Task 9 verifies this).
Dependencies. Task 1.

References. mvp.md lines 454-495. Memory: schema-parity rule.

Task 8. Wire condition enforcement through the existing condition-registry
Goal. Every supported condition is enforced via the same condition-registry the gateway uses, with the in-memory CallCounterStore and in-memory KillSwitchManager.

Scope.

packages/euno-mcp/src/pdp.ts: real PolicyDecisionPoint that, given a tools/call request, resolves the matching CapabilityConstraint from the loaded manifest, runs each CapabilityCondition through condition-registry (from @euno/common-core/src/condition-registry.ts), runs argumentSchema through argument-validator, and runs the file/SQL/table validators from capability-validators.
Counter keys: <sessionId>|<toolName>|<resource> (mvp.md §"Session identity"). This mirrors the production IssuanceRateLimitSubject shape so Stage 3 swap-in is mechanical (memory: rate limiting).
KillSwitchManager: in-memory only; expose a CLI subcommand euno-mcp kill <sessionId|all> (Task 9) that flips it.
Unknown condition type reaching the registry at runtime → deny (defence-in-depth — Task 7 should already reject at load time).
On allow: forward to upstream. On deny: return a structured CapabilityDenied response per the MCP error shape; record an OCSF deny record (Task 6).
Acceptance.

Tests for each supported condition: maxCalls (sliding-window across multiple calls in a session), timeWindow, allowedOperations (SQL verb allowlist), allowedExtensions, allowedTables, argumentSchema.
Test: an unknown type injected directly into a constraint at runtime is denied (not allow-by-default).
Test: kill switch flipped mid-session denies all subsequent calls.
Dependencies. Task 7.

References. mvp.md lines 365-380, 484-495. Memory: rate limiting.

Task 9. CLI commands proxy and validate, reusing packages/cli codepath
Goal. The two user-facing commands. validate must reuse the existing manifest-validation codepath in packages/cli so a manifest validates identically locally and (later) in the issuer.

Scope.

packages/euno-mcp/src/cli.ts:
euno-mcp proxy [--policy <file>] [--audit-log <path>] [--transport stdio|http] [--port <n>] [--bind <addr>] -- <upstream-cmd> [args...]
euno-mcp validate <policy-file>
euno-mcp kill <sessionId|all> (helper for testing)
validate MUST call into the same function the existing euno validate CLI uses (currently in packages/cli/src — see line 449-451 of cli/src/index.ts). Do not duplicate logic. If that function is not exported today, expose it from @euno/cli (or move it into @euno/common-core if cli is not Apache-2.0 — verify first; per mvp.md the cli is Apache-2.0 so an import is fine).
Help output is short, opinionated, and shows the two paste-ready examples from mvp.md lines 351-359.
Acceptance.

euno-mcp validate good.yaml exits 0; euno-mcp validate bad.yaml exits non-zero with the same error format as euno validate bad.yaml.
euno-mcp proxy --policy ... -- node mock-upstream.js end-to-end test works from the integration suite (Task 4).
The CLI surface is documented in the README (Task 14).
Dependencies. Tasks 3, 5, 7.

References. mvp.md lines 350-363, 423-426; existing CLI at packages/cli/src/index.ts:449.

Phase C — Weeks 5–6: Ship and Distribute
Task 10. Telemetry (opt-in, off by default, counts only)
Goal. Ship the gate-instrumentation telemetry described in mvp.md §"Telemetry & gate instrumentation" — in v0, not bolted on later.

Scope.

packages/euno-mcp/src/telemetry/: emit anonymous, count-only metrics.
First-run prompt asking yes/no; persist choice to ~/.euno/telemetry. Default: off. No nags.
Schema (no payload contents — counts only): installs, version, OS family, Node major; sessions started; sessions with ≥1 enforcement event; per-condition-type denial counts (just type names: maxCalls, timeWindow, etc.); upstream MCP server name iff it matches an allow-list of known OSS servers (@modelcontextprotocol/server-filesystem, server-postgres, …) — otherwise reported as custom; CLI subcommand invocation counts.
Anonymous install id (crypto.randomUUID()), regenerated per install. No machine fingerprint.
EUNO_TELEMETRY_LOCAL=1 writes the payload to ~/.euno/telemetry.jsonl and sends nothing.
EUNO_TELEMETRY=0 disables outbound entirely (overrides the prompt).
Endpoint URL is configurable via env (EUNO_TELEMETRY_URL) so the production endpoint can be swapped without a release.
packages/euno-mcp/TELEMETRY.md documents the schema, where it goes, why, and how to disable. Linked from the README.
Acceptance.

Unit test: with telemetry off, no network is touched (mock fetch and assert no call).
Unit test: schema documented in TELEMETRY.md is exactly the schema the code emits (snapshot test against the doc — generate doc from code or test matches doc text).
Manual: EUNO_TELEMETRY_LOCAL=1 produces a jsonl record per session.
Dependencies. Tasks 3, 5, 8 (needs hooks into session start and decision).

References. mvp.md lines 672-702.

Task 11. End-to-end test: destructive SQL is blocked before upstream is called
Goal. Encode the README's headline claim ("the agent called the tool with these arguments — upstream never called") as a test that fails if the guarantee regresses.

Scope.

packages/euno-mcp/test/e2e-sql-block.test.ts: spawn the proxy in front of a mock upstream that records every tool call it ever sees. Load a policy with a SQL query_db constraint allowing only SELECT. Send query_db { query: "DROP TABLE users" } from a test client. Assert: client received CapabilityDenied; mock upstream's recorder shows zero query_db invocations; one OCSF deny record is on disk with the right denial code.
Acceptance. Test fails if any future change forwards the call before the policy decision.

Dependencies. Tasks 4, 8.

References. mvp.md §"Enforcement guarantee — document explicitly" (lines 404-412).

Task 12. Confirm Apache→BSL dependency lint covers @euno/mcp
Goal. Make sure the existing dependency-direction lint actually catches a forbidden edge from @euno/mcp to a BSL package, not just common-core → BSL.

Scope.

Locate the existing CI lint script that walks the workspace dependency graph (mvp.md lines 211-220 says it exists).
Add a unit/snapshot test or a self-test that asserts: a synthetic package.json placing @euno/common-infra in @euno/mcp's dependencies, devDependencies, peerDependencies, optionalDependencies, or as a transitive edge causes the script to exit non-zero.
If the script does not currently cover @euno/mcp (because the package didn't exist when it was written), extend its allow-lists / scan roots so it does.
Acceptance. The negative-test invocation of the script fails as expected; the regular CI invocation against the real tree passes.

Dependencies. Task 1.

References. mvp.md lines 211-225.

Task 13. Publish @euno/mcp to npm
Goal. First public release.

Scope.

packages/euno-mcp/package.json: "publishConfig": { "access": "public" }, files whitelist (dist, README.md, LICENSE, TELEMETRY.md), correct main, types, bin paths.
Add a release script (or extend the existing one in the public repo's CI) that runs npm run build, npm test, then npm publish from packages/euno-mcp.
Tag v0.1.0.
Verify npx -y @euno/mcp@0.1.0 --help works against a freshly-installed package on a clean machine (CI matrix: Node 18, 20, 22 on Linux + macOS; Windows is best-effort for v0).
Acceptance. Package is installable; smoke test from a fresh npm init in /tmp succeeds.

Dependencies. All previous tasks.

References. mvp.md lines 428-434.

Task 14. README + distribution copy
Goal. The README is the conversion surface. mvp.md is prescriptive: lead with a 15-line before/after, include the exact paste-into-claude_desktop_config.json line.

Scope.

packages/euno-mcp/README.md:
First paragraph: the pitch — "Add guardrails to any MCP server in 5 minutes. No infrastructure required."
Section "Before / After": ≤15 lines showing an agent blocked from a destructive SQL call.
Section "Drop-in usage": the exact stdio paste-line for claude_desktop_config.json and the HTTP form for LangChain.js (mvp.md lines 351-359).
Section "Enforcement guarantee": explicit statement that enforcement is on the args the agent sent, not on the underlying op (mvp.md lines 404-412). Three sentences max.
Section "Compatibility": pinned MCP SDK version, supported MCP protocol revisions (Task 2).
Section "Telemetry": one paragraph + link to TELEMETRY.md.
Section "License": Apache-2.0; relationship to the BSL gateway is not mentioned (mvp.md line 267-272: no comments pointing at the private repo).
One launch post draft at packages/euno-mcp/docs/launch-post.md — title from mvp.md line 431: "How I stopped my LangChain agent from destroying my dev database." Owned by marketing for the actual posting.
Acceptance. README renders cleanly on npmjs.com; before/after snippet is copy-pasteable; no references to BSL packages or the private repo.

Dependencies. Tasks 1, 9, 10.

References. mvp.md lines 428-434, 267-272, 404-412.

Task 15. Wire the three Gate-to-Stage-2 measurements
Goal. The promise of "gates pulled by demand" is enforceable only if the three numeric criteria can be read off a dashboard at any time.

Scope.

Define the three criteria as queries over the telemetry endpoint (Task 10):
≥10 unsolicited inbound asks (issues/Discord/email) for richer condition types or cross-process state — manual, but file an ISSUE_TEMPLATE/feature-ask.md with a stage-2-signal label so they can be counted.
Telemetry shows ≥50 distinct installs running ≥1 enforcement event per day for ≥7 consecutive days.
≥1 design-partner conversation with a self-rolled equivalent — manual, tracked in a private CRM/notion.
Add a small scripts/stage2-readiness.ts that prints the current status of #2 from the telemetry store. #1 and #3 are listed but flagged "manual".
Acceptance. Running the script produces a one-line readiness summary. Issue template exists with the right label.

Dependencies. Task 10.

References. mvp.md lines 436-444.

Sequencing & parallelism
Code
Task 1 ─┬─► Task 2
        ├─► Task 3 ─┬─► Task 4
        │           └─► Task 5
        ├─► Task 6
        └─► Task 7 ──► Task 8 ──► Task 9
                                  │
                  ┌───────────────┴────────────┐
                  ▼                            ▼
                Task 10                      Task 11
                  │                            │
                  ▼                            ▼
                Task 15                      Task 12
                                               │
                                               ▼
                                             Task 14 ──► Task 13
Tasks 2, 3, 6, 7 can run in parallel after Task 1.
Tasks 4 and 5 can run in parallel after Task 3.
Tasks 10, 11, 12 can run in parallel after Task 9.
Task 13 (publish) is the last gate.
Definition of done for Stage 1
@euno/mcp v0.1.0 published to npm and installable via npx -y @euno/mcp (Task 13).
Both transports work end-to-end against a real MCP client (Cursor or Claude Desktop) and the LangChain.js MCP integration (Tasks 3, 5, manual smoke).
The five v0 condition types + argumentSchema are enforced via the production condition-registry, not a parallel implementation (Task 8).
Policy-shape and audit-record-shape parity with the gateway is locked: a Stage-1 manifest validates with euno validate and a Stage-1 audit record schema-matches common-core/src/ocsf.ts (Tasks 6, 7, 9).
Telemetry is shipping, opt-in, documented, and feeds the readiness script (Tasks 10, 15).
Apache→BSL dependency lint covers @euno/mcp and is enforced in CI (Task 12).
README leads with the before/after and the paste-line; explicit enforcement guarantee is stated (Task 14).
