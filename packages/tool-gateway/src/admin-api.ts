/**
 * Admin API for Tool Gateway
 * Provides administrative endpoints for kill-switch management and monitoring
 */

import { Router, Request, Response } from 'express';
import { KillSwitchManager, Logger } from '@euno/common';

export interface AdminApiOptions {
  killSwitchManager: KillSwitchManager;
  logger: Logger;
  adminApiKey?: string;
}

/**
 * Create admin API router with authentication
 */
export function createAdminRouter(options: AdminApiOptions): Router {
  const router = Router();
  const { killSwitchManager, logger, adminApiKey } = options;

  // Authentication middleware for admin endpoints
  const authenticateAdmin = (req: Request, res: Response, next: Function): void => {
    if (adminApiKey) {
      const providedKey = req.headers['x-admin-api-key'];
      if (!providedKey || providedKey !== adminApiKey) {
        logger.warn('Unauthorized admin API access attempt', {
          ip: req.ip,
          path: req.path,
        });
        res.status(401).json({
          error: {
            code: 'UNAUTHORIZED',
            message: 'Valid admin API key required',
          },
        });
        return;
      }
    }
    next();
  };

  // Apply authentication to all admin routes
  router.use(authenticateAdmin);

  /**
   * GET /admin/kill-switch/status
   * Get the current status of all kill switches
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
   * Activate the global kill switch (blocks all agents)
   */
  router.post('/kill-switch/global/activate', (_req: Request, res: Response) => {
    try {
      killSwitchManager.activateGlobalKill();
      logger.warn('Global kill switch activated via admin API');
      res.json({ message: 'Global kill switch activated' });
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
   * Deactivate the global kill switch
   */
  router.post('/kill-switch/global/deactivate', (_req: Request, res: Response) => {
    try {
      killSwitchManager.deactivateGlobalKill();
      logger.info('Global kill switch deactivated via admin API');
      res.json({ message: 'Global kill switch deactivated' });
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
   * Kill a specific session
   */
  router.post('/kill-switch/session/:sessionId/kill', (req: Request, res: Response): void => {
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
      logger.warn('Session killed via admin API', { sessionId });
      res.json({ message: `Session ${sessionId} has been killed` });
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
   * Kill a specific agent
   */
  router.post('/kill-switch/agent/:agentId/kill', (req: Request, res: Response): void => {
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
      logger.warn('Agent killed via admin API', { agentId });
      res.json({ message: `Agent ${agentId} has been killed` });
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
   * Revive a killed session
   */
  router.post('/kill-switch/session/:sessionId/revive', (req: Request, res: Response): void => {
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
      logger.info('Session revived via admin API', { sessionId });
      res.json({ message: `Session ${sessionId} has been revived` });
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
   * Revive a killed agent
   */
  router.post('/kill-switch/agent/:agentId/revive', (req: Request, res: Response): void => {
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
      logger.info('Agent revived via admin API', { agentId });
      res.json({ message: `Agent ${agentId} has been revived` });
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
   * Reset all kill switches (use with caution)
   */
  router.post('/kill-switch/reset', (_req: Request, res: Response) => {
    try {
      killSwitchManager.resetAll();
      logger.warn('All kill switches reset via admin API');
      res.json({ message: 'All kill switches have been reset' });
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

  return router;
}
