/**
 * @euno/mcp — audit module public API.
 *
 * Exports the HMAC key management, local signer, and JSONL audit sink used to
 * produce the tamper-evident MCP proxy audit trail.  All exports are
 * Apache-2.0; no BSL dependencies are introduced.
 *
 * @module
 */

export {
  EUNO_STATE_DIR,
  DEFAULT_KEY_PATH,
  HmacKeyError,
  loadOrCreateHmacKey,
} from './hmac-key';

export {
  LOCAL_HMAC_KEY_ID,
  LOCAL_HMAC_ALGORITHM,
  LocalHmacSigner,
} from './hmac-signer';

export type {
  McpAuditRecord,
  SignedMcpAuditEvent,
  McpAuditSink,
  LocalAuditSinkOptions,
} from './audit-sink';

export {
  NullAuditSink,
  LocalAuditSink,
  DEFAULT_AUDIT_LOG_PATH,
  DEFAULT_ROTATE_BYTES,
  createLocalAuditSink,
  verifyAuditEvent,
} from './audit-sink';
