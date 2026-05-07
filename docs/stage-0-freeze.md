# Stage 0 Feature Freeze

> **Status:** Active — effective immediately.  
> **Context:** See [docs/mvp.md § Stage 0](./mvp.md#stage-0-stop-the-bleeding-on-the-existing-codebase) for the full rationale.

---

## What is frozen

The following packages are **feature-frozen** for the duration of Stage 0 and
until the gate to Stage 1 is cleared:

| Package | Owner team |
|---|---|
| `packages/tool-gateway` | `@edgeobs/euno-dp` |
| `packages/capability-issuer` | `@edgeobs/euno-cp` |
| `packages/common` | `@edgeobs/euno-cp` + `@edgeobs/euno-dp` |
| `packages/agent-runtime` | `@edgeobs/euno-dp` |
| `packages/framework-adapters` | `@edgeobs/euno-dx` |

## What the freeze means

A PR targeting a frozen package is acceptable **only** if it falls into one of
these three categories:

1. **Security fix** — a CVE, GHSA, or internally-identified vulnerability.
2. **Dependency bump** — updating a transitive or direct dependency version
   (patch or minor); no new runtime dependencies introduced.
3. **Design-partner-driven change** — a concrete request from a named,
   identified design partner (cite the partner and the ticket in the PR
   description).

Anything else — new features, refactors, additional abstractions, "while
I'm in here" cleanups — must wait until Stage 1 is green-lit or until the
freeze is explicitly lifted by `@edgeobs/euno-leads`.

## Why this freeze exists

The repository contains ~37 k LOC of Stage-5 infrastructure with no
Stage-1 buyers using it yet.  Every maintenance hour spent extending that
infrastructure is an hour not spent on the wedge product (the `@euno/mcp`
package targeted at individual developers).  The freeze converts the default
behaviour — building outwards — into an explicit opt-in that requires
justification.

## PR-review checklist for frozen packages

When reviewing a PR that touches a frozen package, the reviewer **must**
confirm all of the following before approving:

- [ ] The PR description clearly states which freeze category applies
      (security fix / dependency bump / design-partner-driven).
- [ ] If design-partner-driven: the partner is named and a ticket or
      conversation link is included.
- [ ] No new npm runtime dependencies are introduced (devDependencies for
      test tooling are fine).
- [ ] No new exported types, functions, or classes are added that are not
      strictly required by the stated change.
- [ ] No other frozen package is changed as a side-effect unless it has its
      own checklist item above.
- [ ] CI is green (build + tests) after the change.

> **Reviewer note:** If you are unsure whether a change qualifies, ask
> `@edgeobs/euno-leads` before approving.  When in doubt, defer.

## Quarantined packages

Four packages are additionally quarantined — they are kept building in CI
but receive no further investment until a Stage-4 customer pays for them.
Each carries a `STATUS.md` explaining this.  See:

- [`packages/partner-issuer-sim/STATUS.md`](../packages/partner-issuer-sim/STATUS.md)
- [`packages/db-token-service/STATUS.md`](../packages/db-token-service/STATUS.md)
- [`packages/storage-grant-service/STATUS.md`](../packages/storage-grant-service/STATUS.md)
- [`packages/posture-emitter/STATUS.md`](../packages/posture-emitter/STATUS.md)

## MCP SDK pin

The exact `@modelcontextprotocol/sdk` version and support-window policy that
Stage 1 will target are recorded in [`docs/mcp-support.md`](./mcp-support.md).

## Lifting the freeze

The freeze is lifted automatically when the Stage 1 gate is cleared (see
[docs/mvp.md § Stage 0](./mvp.md#stage-0-stop-the-bleeding-on-the-existing-codebase)).
`@edgeobs/euno-leads` may also lift the freeze on a per-package basis by
updating this file and merging the change through the normal CODEOWNERS
review process.
