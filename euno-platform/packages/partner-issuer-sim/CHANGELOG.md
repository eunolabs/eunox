# Changelog — partner-issuer-sim

All notable changes to this package will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.0.0] — Stage 5 GA

**Milestone:** Partner federation promoted from design-partner prototype to
production-ready enterprise capability (Stage 5, Task 3).

### Changed

- Package status updated from **Quarantined** to **GA**.  The `STATUS.md`
  quarantine notice has been replaced with a production-ready status block.
- Version bumped from `0.1.0` to `1.0.0`.

### Added

- `docs/ADAPTERS.md` §"Partner Federation" — operator guide for DID
  registration, pin attestation, circuit-breaker tuning, and revocation.
- `docs/self-host.md` §12.2 "Partner DID federation" — self-host runbook
  including full circuit-breaker metrics reference.
- `integration-tests/tests/partner-federation.test.ts` — five new integration
  tests covering the happy path, circuit-breaker trip/recovery, untrusted DID
  rejection, and pin-mismatch denial.
- `euno_partner_did_circuit_breaker_state{did, state}` Prometheus gauge
  exposed on the gateway `/metrics` endpoint (1 = current state, 0 otherwise).

### Fixed

- The gateway's `PartnerIssuerResolver` now exposes
  `getCircuitBreakerStates()` so Prometheus collection does not require
  internal-state access.

## [0.1.0] — Initial prototype

Initial in-process integration-test harness for the cross-org trust chain.
Not production-ready; quarantined pending a named enterprise customer request.
