/**
 * Jest global setup for capability-issuer tests.
 *
 * `tests/issuer.test.ts` imports the Express `app` directly from
 * `src/index.ts`, which calls `loadConfigOrExit` at module-load time.
 * Jest `setupFiles` run before any test module is required, so we set the
 * minimum env vars here so the config validator does not call
 * `process.exit(1)` during import.
 *
 * All Azure / AWS / GCP service calls in those tests are mocked via
 * `jest.mock()`, so these values never reach a real endpoint.
 */

// Required when SIGNING_PROVIDER=azure-keyvault (the default).
process.env['AZURE_KEYVAULT_URL'] =
  process.env['AZURE_KEYVAULT_URL'] ?? 'https://test-vault.vault.azure.net/';

// Ensure NODE_ENV is set to 'development' (the config schema only accepts
// development | staging | production; 'test' is not a valid value).
if (!process.env['NODE_ENV'] || process.env['NODE_ENV'] === 'test') {
  process.env['NODE_ENV'] = 'development';
}
