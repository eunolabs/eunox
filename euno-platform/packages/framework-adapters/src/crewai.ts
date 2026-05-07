/**
 * CrewAI adapter: tool wrapper + task lifecycle hooks.
 *
 * Sprint-2 DX deliverable: *"CrewAI tool wrappers plus task lifecycle
 * hooks"* (see `docs/execution-plan.md`, Sprint 2 Team DX).
 *
 * CrewAI's tool surface centres on the `BaseTool`/`Tool` class with a
 * `run(args)` method, plus `before_kickoff` / `after_kickoff` callbacks
 * fired around each task's execution. We expose:
 *
 *   1. `wrapAsCrewAITool(runtime, binding)` — produces an object that
 *      satisfies the JS port's `Tool` shape (`name`, `description`,
 *      `func`/`run`). Each call routes through the Euno gateway with
 *      the configured capability tool / resource.
 *
 *   2. `EunoCrewAITaskLifecycle` — exposes `beforeKickoff(task)` and
 *      `afterKickoff(task, result)` hooks that emit correlation-tagged
 *      audit events around each task and refuse to start a task when
 *      the control plane has terminated the agent.
 *
 * Cloud-agnosticism: the adapter delegates entirely to the
 * `CapabilityRuntime` interface — neither the tool wrapper nor the
 * lifecycle hooks reference any specific cloud, so a CrewAI crew
 * configured against any of the three identity providers (Azure AD,
 * AWS Cognito, GCP Identity) works without code changes.
 */

import {
  CapabilityRuntime,
  ToolBinding,
  CapabilityDenialError,
  invokeBoundTool,
  newCorrelationId,
  isCapabilityRuntime,
} from './types';

/**
 * Minimal structural shape of a CrewAI tool. The JS port and the
 * Python-via-binding variants both expose at least these fields, and
 * CrewAI's executor reads them by name (duck-typing), so the wrapper
 * is portable across versions.
 */
export interface CrewAICompatibleTool {
  name: string;
  description: string;
  /** CrewAI's primary tool entry point. Receives whatever the agent supplies. */
  func(args: unknown): Promise<unknown>;
  /** Some CrewAI distributions use `run` instead of `func`; we expose both. */
  run(args: unknown): Promise<unknown>;
  /** Optional argument-shape hint surfaced to the LLM for tool selection. */
  argsSchema?: Record<string, unknown>;
}

/**
 * Wrap a single Euno {@link ToolBinding} as a CrewAI-compatible tool.
 *
 * The returned tool's `func`/`run` returns the gateway response data
 * verbatim (CrewAI consumes both strings and structured objects), with
 * one exception: any {@link CapabilityDenialError} is re-raised so
 * CrewAI's `on_error` / task-failure paths see the structured denial
 * rather than a stringified message.
 */
export function wrapAsCrewAITool(
  runtime: CapabilityRuntime,
  binding: ToolBinding
): CrewAICompatibleTool {
  if (!isCapabilityRuntime(runtime)) {
    throw new TypeError(
      'wrapAsCrewAITool: `runtime` must satisfy the CapabilityRuntime interface.'
    );
  }
  if (!binding || typeof binding.frameworkToolName !== 'string' || !binding.frameworkToolName) {
    throw new TypeError('wrapAsCrewAITool: `binding.frameworkToolName` is required.');
  }
  if (typeof binding.gatewayTool !== 'string' || !binding.gatewayTool) {
    throw new TypeError('wrapAsCrewAITool: `binding.gatewayTool` is required.');
  }

  const run = async (args: unknown): Promise<unknown> => {
    const correlationId = newCorrelationId();
    return invokeBoundTool(runtime, binding, args, correlationId);
  };

  return {
    name: binding.frameworkToolName,
    description:
      binding.description ??
      `Euno-governed tool: ${binding.gatewayTool}` +
        (binding.gatewayResource ? ` (${binding.gatewayResource})` : ''),
    argsSchema: binding.argsSchema,
    func: (args) => run(args),
    run: (args) => run(args),
  };
}

/** Bulk-wrap helper. */
export function wrapAsCrewAITools(
  runtime: CapabilityRuntime,
  bindings: readonly ToolBinding[]
): CrewAICompatibleTool[] {
  return bindings.map((b) => wrapAsCrewAITool(runtime, b));
}

/**
 * Subset of a CrewAI Task that the lifecycle hooks read. CrewAI Tasks
 * carry richer state (agent, expected output, etc.) but the hooks only
 * need a stable identifier for correlation.
 */
export interface CrewAITaskHandle {
  id?: string;
  description?: string;
}

/**
 * Audit event emitted by the lifecycle hooks. Mirrors the LangChain /
 * MAF callback events so a single observability sink can consume all
 * three frameworks.
 */
export interface CrewAITaskAuditEvent {
  phase: 'task-start' | 'task-end' | 'task-error';
  taskId?: string;
  taskDescription?: string;
  correlationId: string;
  ts: string;
  errorCode?: string;
  statusCode?: number;
  errorMessage?: string;
}

export type CrewAITaskAuditSink = (event: CrewAITaskAuditEvent) => void;

/**
 * CrewAI task lifecycle hooks.
 *
 * The class is stateful: it remembers the correlation ID assigned at
 * `beforeKickoff` so the matching `afterKickoff` event carries the
 * same ID.  Use one instance per crew (or per task pipeline); do not
 * share across concurrent crews unless you wrap each kickoff in its
 * own `beforeKickoff` / `afterKickoff` pair.
 */
export class EunoCrewAITaskLifecycle {
  private readonly runtime: CapabilityRuntime;
  private readonly sink?: CrewAITaskAuditSink;
  private readonly taskCorrelations = new Map<string, string>();

  constructor(runtime: CapabilityRuntime, sink?: CrewAITaskAuditSink) {
    if (!isCapabilityRuntime(runtime)) {
      throw new TypeError(
        'EunoCrewAITaskLifecycle: `runtime` must satisfy the CapabilityRuntime interface.'
      );
    }
    this.runtime = runtime;
    this.sink = sink;
  }

  /**
   * Invoke before a task is dispatched to its agent.
   *
   * Returns the correlation ID assigned to the task so callers that
   * thread it into framework metadata (e.g. `task.metadata`) can do so.
   *
   * @throws {CapabilityDenialError} when the runtime has been
   *   terminated by the control plane — refusing to start the task
   *   honours the kill switch at the outermost layer.
   */
  beforeKickoff(task: CrewAITaskHandle): string {
    const correlationId = newCorrelationId();
    const taskKey = this.keyForTask(task);

    if (this.runtime.isTerminated()) {
      this.sink?.({
        phase: 'task-error',
        taskId: task?.id,
        taskDescription: task?.description,
        correlationId,
        ts: new Date().toISOString(),
        statusCode: 403,
        errorMessage: 'Agent terminated by control plane.',
      });
      throw new CapabilityDenialError({
        message:
          'Agent has been terminated by the Euno control plane; refusing to dispatch CrewAI task.',
        statusCode: 403,
        tool: '<crewai-task>',
        correlationId,
      });
    }

    this.taskCorrelations.set(taskKey, correlationId);
    this.sink?.({
      phase: 'task-start',
      taskId: task?.id,
      taskDescription: task?.description,
      correlationId,
      ts: new Date().toISOString(),
    });
    return correlationId;
  }

  /**
   * Invoke after a task completes (successfully or otherwise).
   *
   * `error` is the raw thrown value, if any; we pass through the
   * structured fields of {@link CapabilityDenialError} into the audit
   * event so denials are first-class observable events.
   */
  afterKickoff(task: CrewAITaskHandle, _result?: unknown, error?: unknown): void {
    const taskKey = this.keyForTask(task);
    const correlationId = this.taskCorrelations.get(taskKey) ?? newCorrelationId();
    this.taskCorrelations.delete(taskKey);

    if (error) {
      const denial = error instanceof CapabilityDenialError ? error : undefined;
      this.sink?.({
        phase: 'task-error',
        taskId: task?.id,
        taskDescription: task?.description,
        correlationId,
        ts: new Date().toISOString(),
        errorCode: denial?.errorCode,
        statusCode: denial?.statusCode,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      return;
    }

    this.sink?.({
      phase: 'task-end',
      taskId: task?.id,
      taskDescription: task?.description,
      correlationId,
      ts: new Date().toISOString(),
    });
  }

  /**
   * Stable key for the task → correlation map. We prefer `task.id`
   * when present (CrewAI assigns UUIDs) and fall back to a description-
   * based hash so the hooks still work for ad-hoc tasks constructed
   * inline. Empty/missing identifiers degrade to a placeholder; in
   * that case the correlation map degenerates to "last task wins",
   * which is fine for sequentially-executed crews.
   */
  private keyForTask(task: CrewAITaskHandle): string {
    if (task && typeof task.id === 'string' && task.id) return task.id;
    if (task && typeof task.description === 'string' && task.description) {
      return `desc:${task.description}`;
    }
    return '<anonymous>';
  }
}
