/**
 * Kill-Switch Manager
 * Implements emergency shutdown capabilities for agent systems
 * "Place kill switches in a control plane outside the agent's runtime"
 */

import { KillSwitchManager, KillSwitchConfig } from './types';
import { Logger } from './logger';

/**
 * Implementation of kill-switch functionality
 * Supports global, session-level, and agent-level kill switches
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
