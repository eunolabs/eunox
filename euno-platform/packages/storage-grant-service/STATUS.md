# STATUS — storage-grant-service

**Status: GA (General Availability) — Stage-5 Task 7.**

This package manages storage-layer capability grants (e.g. authorising an
agent to read or write a specific blob container or S3 bucket). It graduated
to GA as part of
[Stage 5 — Enterprise Deployment](../../docs/self-host.md#127-storage-grant-service).

## What this means for contributors

- **New features** are welcome via the normal PR process.
- **CI must keep this package building and all tests passing.**
- **Breaking API changes** require a major-version bump and a corresponding
  update to `docs/self-host.md` §12.7.

## Reference

See [docs/self-host.md §12.7](../../docs/self-host.md#127-storage-grant-service)
for configuration and integration guidance.
