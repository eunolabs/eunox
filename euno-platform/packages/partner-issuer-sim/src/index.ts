/**
 * Public package entry point for `@euno/partner-issuer-sim`.
 *
 * Exposes the app factory and key utilities so integration tests can mount
 * the partner sim in-process. The container entry point is `server.ts`.
 */

export { createPartnerApp, type PartnerAppConfig } from './app';
export { loadOrCreateKey, type PartnerKeyMaterial } from './keys';
