/**
 * Barrel re-exports for the `issuance/` modules. Lets the orchestrator
 * (and tests) import collaborators with a single import path while
 * keeping each module's responsibilities separate on disk.
 *
 * See `docs/IMPROVEMENTS_AND_REFACTORING.md` § R-1.
 */

export * from './consent';
export * from './manifest';
export * from './role-resolution';
export * from './payload-builder';
export * from './signer-pipeline';
export * from './posture';
export * from './attenuation';
export * from './conditions';
