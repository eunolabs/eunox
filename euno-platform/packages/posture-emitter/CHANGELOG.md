# Changelog — @euno/posture-emitter

All notable changes to this package will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — Stage 5 GA

**Milestone:** Posture emitter promoted from quarantine to production-ready
enterprise capability (Stage 5, Task 4 / Task 6).

### Changed

- Package status updated from **Quarantined** to **Stable**.  The `STATUS.md`
  quarantine notice has been replaced with a v1.0.0 stability contract.
- Version bumped from `0.1.0` to `1.0.0`.

### Added

- `DurablePostureEmitter` — SQLite WAL-backed emitter with exponential
  back-off retry, dead-letter tracking, and guaranteed-delivery semantics.
  Recommended for production use.
- `PostureEmitter` — best-effort, non-persistent emitter retained for
  lightweight or embedded contexts.
- `PostureEmitterPlugin` shim in `tool-gateway` converts
  `SignedAuditEvidence` → `AgentInventoryRecord` and wires into the audit
  pipeline's `onSigned` callback.
- `POSTURE_EMITTER_ENABLED` environment variable; gateway bootstrap step 11a
  builds and starts `DurablePostureEmitter` when set.
- `euno_posture_emitter_queue_depth` and `euno_posture_emitter_retry_total`
  Prometheus gauges exposed on the gateway `/metrics` endpoint.
- 12 unit tests in
  `euno-platform/packages/tool-gateway/tests/posture-emitter-plugin.test.ts`
  covering the evidence-to-inventory-record conversion and fail-open
  queue-full behaviour.
- `docs/self-host.md` §"Stage 5 — Posture Emitter" — operator instructions
  for enabling, configuring, and monitoring the emitter.

### Stability contract (from v1.0.0 onwards)

Fields present in `1.0.0` of `AgentInventoryRecord`, `DurablePostureEmitter`,
and `PostureEmitter` will not be removed before `2.0.0`.

## [0.1.0] — Initial prototype

Initial quarantined prototype.  Not production-ready; held pending a named
enterprise customer request requiring AI-posture inventory feed integration
(Defender CSPM / Security Hub / SCC).
