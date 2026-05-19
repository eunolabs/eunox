# STATUS — posture-emitter

**Status: Stable — v1.0.0**

This package emits posture records (a tamper-evident audit side-channel)
alongside capability issuance.  The durable WAL-queue implementation and
Prometheus metrics it provides are part of the Stage-5 compliance tier.

## v1.0.0 Stability Contract

- **Fields present in `1.0.0`** of `AgentInventoryRecord`, `DurablePostureEmitter`,
  and `PostureEmitter` will not be removed before `2.0.0`.
- **`DurablePostureEmitter`** is the production-recommended emitter; it provides
  SQLite WAL-backed guaranteed delivery with exponential back-off retry and
  dead-letter tracking.
- **`PostureEmitter`** (best-effort, no persistence) remains available for
  lightweight or embedded contexts.
- The `onSigned` gateway wiring is implemented in
  `euno-platform/packages/tool-gateway/src/posture-emitter-plugin.ts` and
  produces `AgentInventoryRecord` from `SignedAuditEvidence` for every
  signed enforcement event.

## Production wiring

Gateway bootstrap wires a `DurablePostureEmitter` (controlled by
`POSTURE_EMITTER_ENABLED=true`) into the audit pipeline's `onSigned` callback.
See `docs/self-host.md` §"Stage 5 — Posture Emitter" for operator instructions.

## Reference

See [docs/stage5executionplan.md §4.4](../../docs/stage5executionplan.md)
and [docs/sprint-3-4-gaps/09-ai-posture-inventory.md](../../docs/sprint-3-4-gaps/09-ai-posture-inventory.md)
for the full design and field-mapping rationale.
