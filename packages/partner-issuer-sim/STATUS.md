# STATUS — partner-issuer-sim

**Status: Quarantined — design-partner driven, not on the roadmap.**

This package simulates a partner capability issuer for local development and
integration testing.  It exists to exercise the DID-based trust chain that
belongs to Stage 4 of the [staged execution plan](../../docs/mvp.md#stage-0-stop-the-bleeding-on-the-existing-codebase).

## Policy

- **No new features** will be added without a named, paying user who has
  explicitly requested the feature.
- **CI must keep this package building and all tests passing.**  Do not
  remove it from the workspace or mark it `private` to skip CI.
- **Do not invest further** engineering time here until a Stage-4 customer
  engagement justifies it.

## What this means for contributors

PRs that add features, new abstractions, or additional test coverage to this
package will be closed without merge.  Bug fixes that affect CI are
acceptable.  Dependency bumps driven by security advisories are acceptable.

## Reference

See [docs/mvp.md § Stage 0](../../docs/mvp.md#stage-0-stop-the-bleeding-on-the-existing-codebase)
and [docs/stage-0-freeze.md](../../docs/stage-0-freeze.md) for the full triage
rationale and the PR-review checklist that applies to all frozen packages.
