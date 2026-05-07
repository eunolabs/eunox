/**
 * `/api/v1/tools/invoke` route
 * ---------------------------------------------------------------------------
 * Used by the agent runtime to invoke tools with capability tokens. The
 * action is derived server-side from a registry (never trust the client) and
 * the resource is canonicalised to `tool://<name>` so authorisation is
 * always evaluated against the *actual* tool being invoked.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 *
 * R-7 update: the in-file `TOOL_ACTION_REGISTRY` has been lifted into the
 * pluggable {@link ActionResolver} interface in `@euno/common` so the same
 * tool → action vocabulary is shared between the gateway and any other
 * caller (e.g. issuer-side tooling). The legacy registry remains
 * accessible as `DEFAULT_TOOL_ACTIONS` in `@euno/common/action-resolver`.
 */

import { Request, Response, NextFunction, Router } from 'express';
import {
  ActionResolver,
  BUILTIN_ACTION_RESOLVER,
  DEFAULT_TOOL_ACTIONS,
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
  createLogger,
} from '@euno/common';
import { EnforcementEngine } from '../enforcement';

type Logger = ReturnType<typeof createLogger>;

/**
 * Reconstruct the URL the agent runtime dialled when posting to
 * `/api/v1/tools/invoke`, used as the canonical `htu` for DPoP proof
 * verification (F-2).
 *
 * Security boundary: we deliberately use Express's `req.protocol` and
 * `req.hostname`, which only honour `X-Forwarded-Proto` /
 * `X-Forwarded-Host` when `app.set('trust proxy', …)` has been
 * configured by the operator (see `TRUST_PROXY` in the gateway
 * config and `app-factory.ts`). Reading those headers
 * unconditionally would let any caller who can reach the gateway
 * directly spoof the proof's `htu` to whatever URL they chose to
 * sign — defeating the sender-constrained URL binding instead of
 * verifying the actual request target.
 *
 * `req.hostname` strips any port from the host header. Production
 * deployments behind a load balancer terminate TLS on a standard
 * port (443 / 80) which is implicit in the URL the agent signed,
 * so omitting the port is correct. For non-standard ports the
 * agent's `gatewayUrl` and the gateway's incoming `Host` need to
 * agree (they do by construction — see `agent-runtime` config).
 */
function reconstructToolsRequestUrl(req: Request): string {
  const proto = req.protocol || 'http';
  const host = req.hostname || 'localhost';
  return `${proto}://${host}${req.originalUrl}`;
}

/**
 * Server-side tool registry: maps known tool names to their required action.
 * Re-exported from `@euno/common` so existing imports keep working but the
 * canonical source is now the {@link ActionResolver} configuration loaded
 * from `ACTION_RESOLVER_FILE`.
 *
 * @deprecated Configure tool actions on the {@link ActionResolver} instead.
 */
export const TOOL_ACTION_REGISTRY: Readonly<Record<string, string>> = DEFAULT_TOOL_ACTIONS;

/**
 * Resolves the required action type for a given tool name.
 *
 * @deprecated Inject an {@link ActionResolver} and call its
 * {@link ActionResolver.fromToolInvocation} instead. Retained as a thin
 * wrapper for back-compat.
 */
export function resolveToolAction(
  tool: string,
  resolver: ActionResolver = BUILTIN_ACTION_RESOLVER,
): string {
  return resolver.fromToolInvocation({ tool });
}

export interface ToolsRouterOptions {
  enforcementEngine: EnforcementEngine;
  logger: Logger;
  /**
   * Pluggable resolver used to derive the capability action from the
   * named tool (R-7). When omitted, the in-process
   * {@link BUILTIN_ACTION_RESOLVER} preserves the legacy behaviour.
   */
  actionResolver?: ActionResolver;
}

export function createToolsRouter(opts: ToolsRouterOptions): Router {
  const { enforcementEngine, logger } = opts;
  const actionResolver = opts.actionResolver ?? BUILTIN_ACTION_RESOLVER;
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

        // Derive action from the injectable resolver (R-7). The
        // default implementation reproduces the legacy in-process
        // tool registry; deployments that ship `ACTION_RESOLVER_FILE`
        // can extend or override the mapping for their own tools.
        const action = actionResolver.fromToolInvocation({ tool, args });

        // Canonicalise resource server-side from the actual tool being invoked.
        // Never trust a client-supplied resource value.
        const canonicalResource = `tool://${tool}`;

        // F-2: forward the DPoP proof if present. The agent runtime
        // sends one alongside the bearer token whenever the token is
        // sender-constrained (cnf.jkt). The bound URL is the URL the
        // agent called — reconstructed from the inbound request.
        const dpopHeader = req.headers['dpop'];
        const dpopProof = Array.isArray(dpopHeader) ? dpopHeader[0] : dpopHeader;
        const validationRequest: ValidateActionRequest = {
          token,
          action: action as ValidateActionRequest['action'],
          resource: canonicalResource,
          context: {
            tool,
            args,
            agentId: req.headers['x-agent-id'],
          },
          ...(typeof dpopProof === 'string' && dpopProof.length > 0
            ? {
                dpop: {
                  proof: dpopProof,
                  httpMethod: req.method,
                  httpUrl: reconstructToolsRequestUrl(req),
                },
              }
            : {}),
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
