/**
 * Kill-Switch Manager
 * Implements emergency shutdown capabilities for agent systems
 * "Place kill switches in a control plane outside the agent's runtime"
 *
 * The {@link DefaultKillSwitchManager} below is an **in-process** manager
 * suitable for single-instance deployments and local development.  In
 * multi-instance / production deployments use
 * {@link RedisKillSwitchManager} (or wire your own implementation of
 * {@link KillSwitchManager}) so a kill issued on one gateway pod is
 * visible to every other pod – otherwise an emergency stop on pod A
 * keeps allowing requests on pod B.  See `docs/DISTRIBUTED_KILL_SWITCH.md`
 * for the full architecture and operational guidance.
 */

import { KillSwitchManager, KillSwitchConfig } from './types';
import { Logger } from './logger';

/**
 * In-process implementation of kill-switch functionality.
 *
 * Supports global, session-level, and agent-level kill switches.  All
 * state lives in this Node process only – it is **not** shared across
 * gateway replicas.  Use this only for single-instance deployments,
 * local development, or as a fallback when Redis is not configured.  For
 * any HA deployment use {@link RedisKillSwitchManager} (constructed via
 * `createKillSwitchManagerFromEnv()`) so kills propagate to every pod.
 */
export class DefaultKillSwitchManager implements KillSwitchManager {
  private config: KillSwitchConfig;
  private logger?: Logger;

  constructor(logger?: Logger) {
    this.config = {
      globalKillSwitch: false,
      killedSessions: new Set<string>(),
      killedAgents: new Set<string>(),
    };
    this.logger = logger;
  }

  /**
   * Check if the global kill switch is active
   */
  isGlobalKillActive(): boolean {
    return this.config.globalKillSwitch;
  }

  /**
   * Activate the global kill switch - blocks all agent requests
   */
  activateGlobalKill(): void {
    this.config.globalKillSwitch = true;
    this.logger?.warn('Global kill switch activated - all agent requests will be blocked');
  }

  /**
   * Deactivate the global kill switch
   */
  deactivateGlobalKill(): void {
    this.config.globalKillSwitch = false;
    this.logger?.info('Global kill switch deactivated - agent requests are now allowed');
  }

  /**
   * Kill a specific session
   */
  killSession(sessionId: string): void {
    this.config.killedSessions.add(sessionId);
    this.logger?.warn('Session killed', { sessionId });
  }

  /**
   * Kill a specific agent
   */
  killAgent(agentId: string): void {
    this.config.killedAgents.add(agentId);
    this.logger?.warn('Agent killed', { agentId });
  }

  /**
   * Check if a session is killed
   */
  isSessionKilled(sessionId: string): boolean {
    return this.config.killedSessions.has(sessionId);
  }

  /**
   * Check if an agent is killed
   */
  isAgentKilled(agentId: string): boolean {
    return this.config.killedAgents.has(agentId);
  }

  /**
   * Check if a request should be blocked
   * Returns true if global kill is active, or if the specific session/agent is killed
   */
  shouldBlock(sessionId?: string, agentId?: string): boolean {
    // Check global kill switch first
    if (this.config.globalKillSwitch) {
      return true;
    }

    // Check session-specific kill
    if (sessionId && this.config.killedSessions.has(sessionId)) {
      return true;
    }

    // Check agent-specific kill
    if (agentId && this.config.killedAgents.has(agentId)) {
      return true;
    }

    return false;
  }

  /**
   * Revive a killed session
   */
  reviveSession(sessionId: string): void {
    this.config.killedSessions.delete(sessionId);
    this.logger?.info('Session revived', { sessionId });
  }

  /**
   * Revive a killed agent
   */
  reviveAgent(agentId: string): void {
    this.config.killedAgents.delete(agentId);
    this.logger?.info('Agent revived', { agentId });
  }

  /**
   * Get the current state of all kill switches
   */
  getStatus(): {
    globalKill: boolean;
    killedSessionCount: number;
    killedAgentCount: number;
  } {
    return {
      globalKill: this.config.globalKillSwitch,
      killedSessionCount: this.config.killedSessions.size,
      killedAgentCount: this.config.killedAgents.size,
    };
  }

  /**
   * Reset all kill switches (use with caution)
   */
  resetAll(): void {
    this.config.globalKillSwitch = false;
    this.config.killedSessions.clear();
    this.config.killedAgents.clear();
    this.logger?.warn('All kill switches reset');
  }
}
