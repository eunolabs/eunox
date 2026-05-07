/**
 * Built-in {@link PolicyBackend} implementations for the `'policy'`
 * condition type (R-4 step 2 / F-10).
 */

export {
  OPA_HTTP_BACKEND_NAME,
  createOpaHttpBackend,
  OpaHttpBackendConfig,
  OpaHttpBackendOptions,
} from './opa-http';
