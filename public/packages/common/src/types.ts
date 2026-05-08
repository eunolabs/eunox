/**
 * Back-compat re-export entry point.
 *
 * Historically `@euno/common`'s entire public type surface lived in this
 * file. As part of R-8 ("Split wire types from runtime types in
 * `@euno/common`", `docs/IMPROVEMENTS_AND_REFACTORING.md`) the
 * definitions were moved into two purpose-built modules:
 *
 *  - {@link "./wire"} — JWT/HTTP wire-shape types (the contract with
 *    external systems).
 *  - {@link "./runtime"} — In-process service interfaces, user/session
 *    context, posture records, and configuration shapes.
 *
 * This module remains as a single re-export so existing
 * `import { ... } from '@euno/common'` (which re-exports `./types`) and
 * any code that still imports `./types` directly continues to compile
 * unchanged. New code SHOULD import from
 * `@euno/common/wire` or `@euno/common/runtime` to declare its
 * dependency direction explicitly.
 */

export * from './wire';
export * from './runtime';
