# `@euno/common` — Compatibility Shim

> **⚠️ DEPRECATED** — This package is now a thin compatibility shim that
> re-exports everything from `@euno/common-core` and `@euno/common-infra`.
> It will be removed after Stage 1 ships.

## Migration

Replace your `@euno/common` imports with the appropriate package:

| What you need | New package | License |
|---|---|---|
| Types, interfaces, in-memory stores, config schema | `@euno/common-core` | Apache-2.0 |
| Redis, Postgres, KMS-backed implementations | `@euno/common-infra` | BSL 1.1 |

### Example

```typescript
// Before
import { Logger, RedisCallCounterStore } from '@euno/common';

// After
import { Logger } from '@euno/common-core';
import { RedisCallCounterStore } from '@euno/common-infra';
```

---

Original documentation below (historical reference only):

## Entry points

The package exposes three importable entry points. New code SHOULD prefer the
narrowest one that fits its needs.

| Specifier               | Surface                                                                                                         | Use it when                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `@euno/common/wire`     | Pure data shapes that travel over the wire: JWT payloads, HTTP request/response envelopes, audit records, storage/DB credential payloads, schema-version constants. No imports of in-process services. | A library, partner SDK, or external client only needs to *speak* the protocol — issue, parse, or validate tokens; describe a manifest; emit audit log records; etc. |
| `@euno/common/runtime`  | In-process service interfaces (`EvidenceSigner`, `IdentityProvider`, `TokenSigner`, `TokenVerifier`, `KillSwitchManager`, `PostureEmitterLike`), the authenticated `UserContext` flowing through the issuer, the `AgentInventoryRecord` emitted to posture surfaces, and the `*Config` shapes consumed at boot. | A service or service-side adapter implements one of the pluggable interfaces or threads `UserContext` through its request pipeline. |
| `@euno/common`          | Back-compat union of both of the above plus the runtime helpers (`ConditionRegistry`, the in-memory and Redis `KillSwitchManager`s, `CallCounterStore`, role mapping, validators, logger, evidence helpers). | Existing code paths and ad-hoc usage where the wire/runtime distinction does not matter. |

The `@euno/common/wire` and `@euno/common/runtime` subpath split separates wire types (JWT/HTTP shapes) from runtime interfaces, so an OpenAPI ↔ TypeScript generator can target `./src/wire.ts` without filtering out runtime declarations.

```ts
// Spec-only consumer (parser, partner SDK, type-generation target):
import type { CapabilityTokenPayload, CapabilityCondition } from '@euno/common/wire';

// Service-side consumer (custom IdP, posture plugin, kill-switch backend):
import type { IdentityProvider, UserContext } from '@euno/common/runtime';

// Existing consumer (no change required):
import { signCapabilityToken } from '@euno/common';
```

## Build & test

```bash
npm run build   # tsc — emits dist/{wire,runtime,index,...}.{js,d.ts}
npm test        # jest
npm run lint    # eslint
```
