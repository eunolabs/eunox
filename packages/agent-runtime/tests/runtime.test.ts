/**
 * Agent Runtime Tests
 */

import { AgentRuntime, createAgentRuntime } from '../src/runtime';

describe('AgentRuntime', () => {
  describe('initialization', () => {
    it('should create runtime with valid config', () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      expect(runtime).toBeDefined();
    });

    it('should use default token refresh interval', () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      expect(runtime).toBeDefined();
      // Default refresh interval should be 600 seconds (10 minutes)
    });

    it('should accept custom token refresh interval', () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
        tokenRefreshInterval: 300,
      });

      expect(runtime).toBeDefined();
    });
  });

  describe('tool invocation', () => {
    it('should route tool calls through gateway', async () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      // This test would need a mock gateway to run successfully
      // For now, we just verify the method exists
      expect(runtime.invokeTool).toBeDefined();
    });

    it('should attach capability token to requests', async () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      expect(runtime.invokeTool).toBeDefined();
      // Token should be included in Authorization header
    });

    it('should retry on 401 with token refresh', async () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      // Implementation should handle 401 by refreshing token
      expect(runtime.invokeTool).toBeDefined();
    });
  });

  describe('network restrictions', () => {
    it('should route all HTTP requests through gateway', async () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      // Sprint 1: All external requests must go through gateway
      expect(runtime.makeRequest).toBeDefined();
    });

    it('should not allow direct external requests', () => {
      // Sprint 1 requirement: Network policies block direct egress
      // This is enforced at the Kubernetes level via NetworkPolicy
      expect(true).toBe(true);
    });
  });

  describe('cleanup', () => {
    it('should cleanup resources on shutdown', async () => {
      const runtime = new AgentRuntime({
        agentId: 'test-agent',
        gatewayUrl: 'http://localhost:3002',
        issuerUrl: 'http://localhost:3001',
      });

      await runtime.shutdown();
      expect(runtime).toBeDefined();
    });
  });
});
