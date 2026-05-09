/**
 * @euno/langchain — LangChain companion package for Euno capability governance.
 *
 * Public API:
 *
 *   - {@link createLocalRuntime}          — async factory: FilePolicySource + ConditionEnforcerPDP + LocalAuditSink
 *   - {@link LocalCapabilityRuntime}      — in-process enforcement runtime
 *   - {@link wrapAsLangChainTool}         — wrap a governed tool as a LangChain-compatible object
 *   - {@link wrapAsLangChainTools}        — bulk wrapper
 *   - {@link EunoLangChainCallbackHandler}— LangChain callback handler for audit correlation
 *   - {@link CapabilityDenialError}       — thrown when a tool call is denied
 *   - {@link newCorrelationId}            — UUID helper for correlation IDs
 *
 * @module
 */

export type {
  LangChainCompatibleTool,
  LocalToolInvocationRequest,
  LocalToolInvocationResult,
  LocalToolDefinition,
} from './types';
export { CapabilityDenialError, newCorrelationId } from './types';

export type { LocalRuntimeOptions } from './runtime';
export { LocalCapabilityRuntime, createLocalRuntime } from './runtime';

export { wrapAsLangChainTool, wrapAsLangChainTools } from './tool';

export type {
  EunoCallbackEvent,
  EunoCallbackSink,
  LangChainCallbacks,
} from './callback';
export { EunoLangChainCallbackHandler } from './callback';
