/**
 * LocalCapabilityRuntime — in-process enforcement for @euno/langchain.
 *
 * Composes the same building blocks used by the euno-mcp proxy:
 *   - {@link FilePolicySource}     — loads the capability manifest from a local YAML/JSON file
 *   - {@link ConditionEnforcerPDP} — enforces conditions (maxCalls, timeWindow, ipRange, …)
 *   - {@link LocalAuditSink}       — appends signed OCSF records to a local JSONL file
 *
 * This gives LangChain users the identical enforcement semantics, denial codes,
 * and audit shape as the full MCP transport — without requiring a separate
 * process or network hop.
 *
 * ## Usage
 *
 * ```ts
 * import { createLocalRuntime, wrapAsLangChainTool } from '@euno/langchain';
 *
 * const runtime = await createLocalRuntime({
 *   policyFile: './euno.policy.yaml',
 *   auditLog:   '~/.euno/audit.jsonl',
 * });
 *
 * const tool = wrapAsLangChainTool(runtime, {
 *   name:        'query_db',
 *   description: 'Run a read-only SQL query',
 *   schema:      { type: 'object', properties: { sql: { type: 'string' } } },
 *   handler:     async ({ sql }) => db.query(String(sql)),
 * });
 * ```
 *
 * @module
 */

import * as crypto from 'crypto';
import * as os from 'os';
import {
  ConditionEnforcerPDP,
  FilePolicySource,
  createLocalAuditSink,
  NullAuditSink,
} from '@euno/mcp';
import type {
  McpAuditSink,
  LocalAuditSinkOptions,
  LocalPolicySource,
} from '@euno/mcp';
import type { LocalToolInvocationRequest, LocalToolInvocationResult } from './types';

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * Options for {@link createLocalRuntime}.
 */
export interface LocalRuntimeOptions {
  /**
   * Path to the capability manifest file (YAML or JSON).
   * The same file format accepted by `euno-mcp proxy --policy <path>`.
   */
  policyFile: string;
  /**
   * Path to the local JSONL audit log.
   *
   * @default `~/.euno/audit.jsonl`
   */
  auditLog?: string;
  /**
   * Maximum audit log file size (bytes) before rotation.
   *
   * @default 100 MiB
   */
  rotateSizeBytes?: number;
  /**
   * Fixed session identifier. When absent a UUID is generated per
   * `createLocalRuntime()` call. All tool invocations through one runtime
   * instance share the same session ID in the audit log.
   */
  sessionId?: string;
  /**
   * Override the policy source. Useful in tests to inject an in-memory policy
   * without touching the file system. When provided, `policyFile` is ignored.
   *
   * @internal
   */
  _policySource?: LocalPolicySource;
  /**
   * Override the audit sink. Useful in tests to capture audit records without
   * touching the file system.
   *
   * @internal
   */
  _auditSink?: McpAuditSink;
}

// ---------------------------------------------------------------------------
// LocalCapabilityRuntime
// ---------------------------------------------------------------------------

/**
 * In-process enforcement runtime for @euno/langchain.
 *
 * Each {@link invokeTool} call:
 *   1. Runs the PDP against the loaded manifest.
 *   2. Records the decision to the local audit log.
 *   3. Returns a {@link LocalToolInvocationResult} indicating allow or deny.
 *
 * The runtime is safe to call concurrently. Counter state (for `maxCalls`
 * conditions) is held in memory and resets on process restart.
 */
export class LocalCapabilityRuntime {
  /** Session identifier shared across all tool calls from this runtime. */
  public readonly sessionId: string;

  private readonly _pdp: ConditionEnforcerPDP;
  private readonly _auditSink: McpAuditSink;
  private _terminated = false;

  /** @internal — use {@link createLocalRuntime} */
  constructor(pdp: ConditionEnforcerPDP, auditSink: McpAuditSink, sessionId: string) {
    this._pdp = pdp;
    this._auditSink = auditSink;
    this.sessionId = sessionId;
  }

  /**
   * Enforce the capability manifest against a tool invocation.
   *
   * Returns a {@link LocalToolInvocationResult}. On denial the result carries
   * the machine-readable `denialCode` and `conditionType` so callers can
   * react programmatically. The decision (allow or deny) is always recorded
   * to the audit log.
   *
   * @throws Never — denial surfaces through the return value, not an exception.
   *   Use {@link wrapAsLangChainTool} for the throwing variant expected by
   *   LangChain's error-handling pipeline.
   */
  async invokeTool(request: LocalToolInvocationRequest): Promise<LocalToolInvocationResult> {
    if (this._terminated) {
      const result: LocalToolInvocationResult = {
        success: false,
        denialCode: 'KILL_SWITCH',
        denialReason: 'Runtime has been terminated',
        conditionType: 'kill',
      };
      await this._auditSink.record({
        sessionId: this.sessionId,
        toolName: request.tool,
        resource: request.resource,
        decision: 'deny',
        denialCode: result.denialCode,
        conditionType: result.conditionType,
        requestId: request.correlationId,
      });
      return result;
    }

    const mcpRequest = {
      method: 'tools/call' as const,
      params: {
        name: request.tool,
        arguments: request.args,
      },
    };
    const pdpCtx = {
      sessionId: this.sessionId,
      sourceIp: request.sourceIp,
    };

    const decision = await this._pdp.decide(mcpRequest, pdpCtx);

    await this._auditSink.record({
      sessionId: this.sessionId,
      toolName: request.tool,
      resource: request.resource,
      decision: decision.allow ? 'allow' : 'deny',
      denialCode: decision.denialCode,
      conditionType: decision.conditionType,
      details: decision.details,
      requestId: request.correlationId,
    });

    if (!decision.allow) {
      return {
        success: false,
        denialCode: decision.denialCode,
        denialReason: decision.reason,
        conditionType: decision.conditionType,
        details: decision.details,
      };
    }

    return { success: true };
  }

  /**
   * Returns `true` when the runtime has been terminated via {@link terminate}.
   *
   * LangChain integrations can call this before each agent step to short-circuit
   * a killed runtime early.
   */
  isTerminated(): boolean {
    return this._terminated;
  }

  /**
   * Immediately terminate this runtime instance.
   *
   * All subsequent {@link invokeTool} calls will be denied with
   * `KILL_SWITCH`. This mirrors the MCP proxy's `euno-mcp kill` command.
   *
   * Also activates the underlying PDP's global kill switch so any shared
   * counter state is consistent.
   */
  terminate(): void {
    this._terminated = true;
    this._pdp.killAll();
  }

  /**
   * Stop the policy file watcher (if any) and flush the audit sink.
   *
   * Call during graceful shutdown to prevent resource leaks.
   */
  async dispose(): Promise<void> {
    this._pdp.dispose();
    await this._auditSink.close();
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a {@link LocalCapabilityRuntime} backed by a local policy file and
 * a local JSONL audit log.
 *
 * The policy file is loaded lazily on the first `invokeTool` call and
 * hot-reloaded whenever the file changes on disk.
 *
 * @example
 * ```ts
 * const runtime = await createLocalRuntime({
 *   policyFile: './euno.policy.yaml',
 * });
 * ```
 */
export async function createLocalRuntime(
  opts: LocalRuntimeOptions,
): Promise<LocalCapabilityRuntime> {
  const sessionId = opts.sessionId ?? crypto.randomUUID();

  // Policy source — use caller-supplied override (useful in tests), otherwise
  // load from the file at opts.policyFile.
  const policySource: LocalPolicySource = opts._policySource
    ? opts._policySource
    : new FilePolicySource({ filePath: opts.policyFile });

  // PDP — wires the policy source with in-memory counter state.
  const pdp = new ConditionEnforcerPDP({ policySource });

  // Audit sink — file-backed unless overridden for tests, or falls back to
  // NullAuditSink when no audit log is configured and no override is given.
  let auditSink: McpAuditSink;
  if (opts._auditSink) {
    auditSink = opts._auditSink;
  } else {
    const sinkOpts: LocalAuditSinkOptions = {};
    if (opts.auditLog) {
      // Expand leading `~` to the user's home directory — Node.js path APIs do
      // not perform shell tilde expansion, so `~/.euno/audit.jsonl` would
      // create a literal `~` directory under cwd without this step.
      sinkOpts.logPath = opts.auditLog.startsWith('~/')
        ? os.homedir() + opts.auditLog.slice(1)
        : opts.auditLog;
    }
    if (opts.rotateSizeBytes !== undefined) sinkOpts.rotateSizeBytes = opts.rotateSizeBytes;

    try {
      auditSink = await createLocalAuditSink(sinkOpts);
    } catch {
      // If the audit sink can't be created (e.g. permissions), fall back to
      // null sink so enforcement still works. Log the error to stderr.
      process.stderr.write(
        '[euno-langchain] Warning: could not create audit sink — falling back to null sink.\n',
      );
      auditSink = new NullAuditSink();
    }
  }

  return new LocalCapabilityRuntime(pdp, auditSink, sessionId);
}
