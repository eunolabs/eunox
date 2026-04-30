/**
 * `/api/v1/tools/invoke` route
 * ---------------------------------------------------------------------------
 * Used by the agent runtime to invoke tools with capability tokens. The
 * action is derived server-side from a registry (never trust the client) and
 * the resource is canonicalised to `tool://<name>` so authorisation is
 * always evaluated against the *actual* tool being invoked.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import { Request, Response, NextFunction, Router } from 'express';
import {
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
} from '@euno/common';
import { EnforcementEngine } from '../enforcement';

type Logger = ReturnType<typeof createLogger>;

/**
 * Server-side tool registry: maps known tool names to their required action.
 * Using an explicit registry prevents misclassification from substring matching
 * and ensures authorisation decisions are based on the actual tool semantics.
 * Unknown tools default to 'execute' (most restrictive default).
 */
export const TOOL_ACTION_REGISTRY: Record<string, string> = {
  // File operations
  read_file: 'read',
  get_file: 'read',
  list_files: 'read',
  list_directory: 'read',
  write_file: 'write',
  create_file: 'write',
  update_file: 'write',
  append_file: 'write',
  delete_file: 'delete',
  remove_file: 'delete',
  // HTTP/API operations
  http_get: 'read',
  http_post: 'write',
  http_put: 'write',
  http_delete: 'delete',
  // Code execution
  run_code: 'execute',
  execute_command: 'execute',
  run_shell: 'execute',
};

/**
 * Resolves the required action type for a given tool name using an explicit
 * server-side registry.  Using a registry instead of substring matching prevents
 * misclassification and ensures authorisation decisions reflect the tool's
 * actual semantics.  Unknown tools default to 'execute', the most restrictive
 * action.
 *
 * @param tool - The tool name to look up (e.g. 'read_file').
 * @returns The action string ('read' | 'write' | 'delete' | 'execute').
 */
export function resolveToolAction(tool: string): string {
  return TOOL_ACTION_REGISTRY[tool] ?? 'execute';
}

export interface ToolsRouterOptions {
  enforcementEngine: EnforcementEngine;
  logger: Logger;
}

export function createToolsRouter(opts: ToolsRouterOptions): Router {
  const { enforcementEngine, logger } = opts;
  const router = Router();

  router.post(
    '/api/v1/tools/invoke',
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const token = parseBearerToken(req.headers.authorization);
        if (!token) {
          throw new CapabilityError(
            ErrorCode.AUTHENTICATION_FAILED,
            'Authorization header with Bearer token is required',
            401,
          );
        }

        if (typeof req.body !== 'object' || req.body === null || Array.isArray(req.body)) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'Request body must be a JSON object',
            400,
          );
        }

        const { tool, args } = req.body as { tool?: unknown; args?: unknown };

        if (typeof tool !== 'string' || tool.length === 0) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'tool parameter is required and must be a non-empty string',
            400,
          );
        }

        // Derive action from the server-side tool registry (not client-supplied).
        const action = resolveToolAction(tool);

        // Canonicalise resource server-side from the actual tool being invoked.
        // Never trust a client-supplied resource value.
        const canonicalResource = `tool://${tool}`;

        const validationRequest: ValidateActionRequest = {
          token,
          action: action as ValidateActionRequest['action'],
          resource: canonicalResource,
          context: {
            tool,
            args,
            agentId: req.headers['x-agent-id'],
          },
        };

        const result = await enforcementEngine.validateAction(validationRequest);

        if (!result.allowed) {
          throw new CapabilityError(
            ErrorCode.AUTHORIZATION_FAILED,
            result.reason || 'Tool invocation not allowed',
            403,
          );
        }

        // In a real implementation, this would invoke the actual tool.
        // For now, return success with mock data.
        logger.info('Tool invoked successfully', {
          tool,
          action,
          resource: canonicalResource,
          agentId: req.headers['x-agent-id'],
        });

        const responseBody: unknown = {
          success: true,
          tool,
          result: {
            message: 'Tool executed successfully (mock implementation)',
            data: args,
          },
        };

        // R-4 step 1: apply the matched capability's response-time
        // obligations (e.g. `redactFields`) before sending. The
        // enforcement engine builds this lobe only when the matched
        // capability declared at least one redact-capable condition,
        // so the cost is paid only by capabilities that asked for it.
        const redacted = result.applyResponseRedactions
          ? result.applyResponseRedactions(responseBody)
          : responseBody;

        res.json(redacted);
      } catch (error) {
        next(error);
      }
    },
  );

  return router;
}
