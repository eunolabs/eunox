/**
 * @euno/framework-adapters
 *
 * Framework-native adapters that route tool calls through the Euno
 * capability gateway. Sprint-2 DX deliverable
 * (`docs/execution-plan.md`).
 *
 * Three adapters live here:
 *
 *   - `./langchain` — `wrapAsLangChainTool`, `wrapAsLangChainTools`,
 *     `EunoLangChainCallbackHandler`.
 *   - `./maf`        — `createEunoFunctionToolMiddleware`,
 *     `createEunoAgentRunMiddleware`.
 *   - `./crewai`     — `wrapAsCrewAITool`, `wrapAsCrewAITools`,
 *     `EunoCrewAITaskLifecycle`.
 *
 * All three sit on top of the cloud-agnostic `AgentRuntime` from
 * `@euno/agent-runtime`, so a single configuration of identity provider
 * and KMS signer (Azure / AWS / GCP) is all that's needed regardless of
 * which framework the application uses.
 */

export * from './types';
export * from './langchain';
export * from './maf';
export * from './crewai';
