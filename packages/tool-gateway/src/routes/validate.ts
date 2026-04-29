/**
 * `/api/v1/validate` route
 * ---------------------------------------------------------------------------
 * Lightweight endpoint that validates a capability token against an arbitrary
 * action / resource pair. Intended for testing and for integrators that want
 * to ask the gateway "would this be allowed?" without actually proxying a
 * request.
 *
 * Part of R-2 from `docs/IMPROVEMENTS_AND_REFACTORING.md`.
 */

import { Request, Response, NextFunction, Router } from 'express';
import {
  ValidateActionRequest,
  CapabilityError,
  ErrorCode,
  parseBearerToken,
} from '@euno/common';
import { EnforcementEngine } from '../enforcement';

export interface ValidateRouterOptions {
  enforcementEngine: EnforcementEngine;
}

export function createValidateRouter(opts: ValidateRouterOptions): Router {
  const { enforcementEngine } = opts;
  const router = Router();

  router.post(
    '/api/v1/validate',
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

        const body = (req.body ?? {}) as Record<string, unknown>;
        const { action, resource, context } = body;
        if (typeof action !== 'string' || action.length === 0) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'action parameter is required and must be a non-empty string',
            400,
          );
        }
        if (typeof resource !== 'string' || resource.length === 0) {
          throw new CapabilityError(
            ErrorCode.INVALID_REQUEST,
            'resource parameter is required and must be a non-empty string',
            400,
          );
        }

        const validationRequest: ValidateActionRequest = {
          token,
          action: action as ValidateActionRequest['action'],
          resource,
          context: context as ValidateActionRequest['context'],
        };

        const result = await enforcementEngine.validateAction(validationRequest);
        res.json(result);
      } catch (error) {
        next(error);
      }
    },
  );

  return router;
}
