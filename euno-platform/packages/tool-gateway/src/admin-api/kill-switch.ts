/**
 * Kill-switch admin route group.
 *
 * Handles all `/kill-switch/*` endpoints:
 *   GET  /kill-switch/status
 *   POST /kill-switch/global/activate
 *   POST /kill-switch/global/deactivate
 *   POST /kill-switch/session/:sessionId/kill
 *   POST /kill-switch/agent/:agentId/kill
 *   POST /kill-switch/session/:sessionId/revive
 *   POST /kill-switch/agent/:agentId/revive
 *   POST /kill-switch/reset
 */

import * as crypto from 'crypto';
import { Router, Request, Response } from 'express';
import { AdminRouterContext } from './context';

/**
 * Mount all kill-switch routes onto `router`.
 *
 * Called from `createAdminRouter` after the authentication middleware has been
 * applied, so every handler here can assume the caller is authenticated.
 */
export function mountKillSwitchRoutes(router: Router, ctx: AdminRouterContext): void {
  const {
    killSwitchManager,
    logger,
    auditLogger,
    usageMeter,
    resolveOperator,
    emitAdminOcsfEvent,
    replayIfIdempotent,
    cacheIdempotentResponse,
    assertTenantScope,
    killSwitchSuccessResponse,
    killSwitchTenantId,
  } = ctx;

  /**
   * GET /admin/kill-switch/status
   * Get the current status of all kill switches.
   */
  router.get('/kill-switch/status', (_req: Request, res: Response) => {
    try {
      const status = killSwitchManager.getStatus();
      res.json(status);
    } catch (error) {
      logger.error('Failed to get kill-switch status', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to get kill-switch status',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/global/activate
   * Activate the global kill switch (blocks all agents on this gateway instance).
   *
   * ⚠️  When the gateway is tenant-scoped (`ADMIN_TENANT_ID` is set) this
   * operation STILL blocks all tenants because the kill switch is gateway-wide.
   * Callers must acknowledge this explicitly by including
   * `"acknowledgesCrossTenantImpact": true` in the request body.
   */
  router.post('/kill-switch/global/activate', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res, /* requiresAcknowledgement */ true)) return;
    try {
      killSwitchManager.activateGlobalKill();
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_global_activated', {
        eventType: 'kill_switch_global_activated',
        operator: operator ?? 'unknown',
        severity: 'CRITICAL',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 5, // Critical
        operator,
        message: 'Global kill switch activated — all agent traffic blocked',
        status: 'Success',
        unmapped: { scope: 'global' },
      });
      logger.warn('Global kill switch activated via admin API', { operator });
      usageMeter?.recordKillSwitchInvocation(killSwitchTenantId(req));
      const { status, body } = killSwitchSuccessResponse('Global kill switch activated');
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to activate global kill switch', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to activate global kill switch',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/global/deactivate
   * Deactivate the global kill switch.
   *
   * Same cross-tenant caveat as activate: when tenant-scoped, the acknowledgement
   * field is required because deactivation restores traffic for ALL tenants.
   */
  router.post('/kill-switch/global/deactivate', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res, /* requiresAcknowledgement */ true)) return;
    try {
      killSwitchManager.deactivateGlobalKill();
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.info('kill_switch_global_deactivated', {
        eventType: 'kill_switch_global_deactivated',
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 1, // Assign Privileges (restoring access)
        severityId: 2, // Low
        operator,
        message: 'Global kill switch deactivated — agent traffic restored',
        status: 'Success',
        unmapped: { scope: 'global' },
      });
      logger.info('Global kill switch deactivated via admin API', { operator });
      const { status, body } = killSwitchSuccessResponse('Global kill switch deactivated');
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to deactivate global kill switch', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to deactivate global kill switch',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/session/:sessionId/kill
   * Kill a specific session.
   *
   * When the gateway is tenant-scoped, the request body MUST include a
   * `tenantId` field matching the configured tenant — this prevents an
   * operator credential for tenant A from killing a session that belongs
   * to tenant B.
   */
  router.post('/kill-switch/session/:sessionId/kill', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
    try {
      const { sessionId } = req.params;
      if (!sessionId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'sessionId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.killSession(sessionId);
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_session_killed', {
        eventType: 'kill_switch_session_killed',
        sessionId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 4, // High
        operator,
        targets: [{ uid: sessionId, type: 'session' }],
        message: `Session "${sessionId}" killed`,
        status: 'Success',
      });
      logger.warn('Session killed via admin API', { sessionId });
      usageMeter?.recordKillSwitchInvocation(killSwitchTenantId(req));
      const { status, body } = killSwitchSuccessResponse(`Session ${sessionId} has been killed`);
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to kill session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to kill session',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/agent/:agentId/kill
   * Kill a specific agent.
   *
   * When the gateway is tenant-scoped, the request body MUST include a
   * matching `tenantId` field.
   */
  router.post('/kill-switch/agent/:agentId/kill', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
    try {
      const { agentId } = req.params;
      if (!agentId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'agentId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.killAgent(agentId);
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_agent_killed', {
        eventType: 'kill_switch_agent_killed',
        agentId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 2, // Revoke Privileges
        severityId: 4, // High
        operator,
        targets: [{ uid: agentId, type: 'agent' }],
        message: `Agent "${agentId}" killed`,
        status: 'Success',
      });
      logger.warn('Agent killed via admin API', { agentId });
      usageMeter?.recordKillSwitchInvocation(killSwitchTenantId(req));
      const { status, body } = killSwitchSuccessResponse(`Agent ${agentId} has been killed`);
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to kill agent', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to kill agent',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/session/:sessionId/revive
   * Revive a killed session.
   */
  router.post('/kill-switch/session/:sessionId/revive', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
    try {
      const { sessionId } = req.params;
      if (!sessionId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'sessionId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.reviveSession(sessionId);
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.info('kill_switch_session_revived', {
        eventType: 'kill_switch_session_revived',
        sessionId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 1, // Assign Privileges (restoring access)
        severityId: 2, // Low
        operator,
        targets: [{ uid: sessionId, type: 'session' }],
        message: `Session "${sessionId}" revived`,
        status: 'Success',
      });
      logger.info('Session revived via admin API', { sessionId });
      const { status, body } = killSwitchSuccessResponse(`Session ${sessionId} has been revived`);
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to revive session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to revive session',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/agent/:agentId/revive
   * Revive a killed agent.
   */
  router.post('/kill-switch/agent/:agentId/revive', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res)) return;
    try {
      const { agentId } = req.params;
      if (!agentId) {
        res.status(400).json({
          error: {
            code: 'INVALID_REQUEST',
            message: 'agentId parameter is required',
          },
        });
        return;
      }

      killSwitchManager.reviveAgent(agentId);
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.info('kill_switch_agent_revived', {
        eventType: 'kill_switch_agent_revived',
        agentId,
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 1, // Assign Privileges (restoring access)
        severityId: 2, // Low
        operator,
        targets: [{ uid: agentId, type: 'agent' }],
        message: `Agent "${agentId}" revived`,
        status: 'Success',
      });
      logger.info('Agent revived via admin API', { agentId });
      const { status, body } = killSwitchSuccessResponse(`Agent ${agentId} has been revived`);
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to revive agent', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to revive agent',
        },
      });
    }
  });

  /**
   * POST /admin/kill-switch/reset
   * Reset ALL kill switches on this gateway instance (use with caution).
   *
   * This is a gateway-wide operation — it clears the global kill flag and
   * removes every individually killed session and agent regardless of tenant.
   * When tenant scoping is active, the cross-tenant acknowledgement field is
   * therefore required to confirm awareness of this full-instance blast radius.
   */
  router.post('/kill-switch/reset', async (req: Request, res: Response): Promise<void> => {
    if (await replayIfIdempotent(req, res)) return;
    if (assertTenantScope(req, res, /* requiresAcknowledgement */ true)) return;
    try {
      killSwitchManager.resetAll();
      const operator = resolveOperator(req);
      const uid = crypto.randomUUID();
      auditLogger.warn('kill_switch_reset_all', {
        eventType: 'kill_switch_reset_all',
        operator: operator ?? 'unknown',
        auditEventId: uid,
      });
      emitAdminOcsfEvent({
        uid,
        activityId: 99, // Other
        severityId: 5, // Critical
        operator,
        message: 'All kill switches reset — all previously blocked sessions/agents are unblocked',
        status: 'Success',
        unmapped: { scope: 'all' },
      });
      logger.warn('All kill switches reset via admin API');
      const { status, body } = killSwitchSuccessResponse('All kill switches have been reset');
      await cacheIdempotentResponse(req, status, body);
      res.status(status).json(body);
    } catch (error) {
      logger.error('Failed to reset kill switches', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'Failed to reset kill switches',
        },
      });
    }
  });
}
