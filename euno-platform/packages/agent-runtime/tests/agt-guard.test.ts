/**
 * Tests for the AGT in-process guard adapter (`createAgtGuard`).
 *
 * Stage-5 execution plan §4.6 specifies four test cases:
 *  1. Guard allows a tool call in scope → forwarded to transport.
 *  2. Guard denies a tool call out of scope → `onDeny` called, transport not
 *     invoked.
 *  3. Guard allows but gateway denies → `onGatewayDeny` called (not `onDeny`);
 *     gateway audit entry is the sole denial record.
 *  4. Integration test: the full Set-D2 flow (guard → gateway → API).
 *
 * All tests use an `InProcessToolTransport` so no HTTP server is needed.
 * Issuer calls are not involved; the `tokenSupplier` option is supplied as a
 * simple synchronous function that returns a pre-loaded token string.
 */

import {
  createAgtGuard,
  InProcessToolTransport,
} from '../src/index';
import type {
  AgtGuardDenyReason,
} from '../src/index';
import type {
  ToolTransportInvokeRequest,
  ToolTransportResponse,
  TransportCredentials,
} from '../src/index';
import type { AgentCapabilityManifest } from '@euno/common';

// ── Fixtures ──────────────────────────────────────────────────────────────────

/** Minimal valid manifest that declares one required and one optional capability. */
function makeManifest(
  overrides?: Partial<AgentCapabilityManifest>,
): AgentCapabilityManifest {
  return {
    agentId: 'agent-guard-test',
    name: 'Guard Test Agent',
    version: '1.0.0',
    requiredCapabilities: [
      { resource: 'db:read', actions: ['read'] },
      { resource: 'storage:read', actions: ['read'] },
    ],
    optionalCapabilities: [
      { resource: 'cache:read', actions: ['read'] },
    ],
    ...overrides,
  };
}

/** Synchronous token supplier that always returns a fixed token string. */
function staticSupplier(token = 'cap-token-fixed'): () => string {
  return () => token;
}

/** Build a mock InProcessToolTransport handler that always succeeds. */
function successHandler(
  data: unknown = { result: 'ok' },
): jest.Mock<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]> {
  return jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>().mockResolvedValue({
    success: true,
    data,
    statusCode: 200,
  });
}

/** Build a mock InProcessToolTransport handler that always returns a gateway denial. */
function gatewayDenyHandler(
  statusCode: number,
  errorCode?: string,
): jest.Mock<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]> {
  return jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>().mockResolvedValue({
    success: false,
    statusCode,
    error: 'Gateway denied',
    errorCode,
  });
}

// ── 1. Guard allows an in-scope tool call ─────────────────────────────────────

describe('createAgtGuard — allow in-scope tool calls', () => {
  it('returns guardResult "allow" and success true for a required capability', async () => {
    const handler = successHandler({ rows: [] });
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: { table: 'users' } });

    expect(result.guardResult).toBe('allow');
    expect(result.success).toBe(true);
    expect(result.statusCode).toBe(200);
    expect(result.denyReason).toBeUndefined();
  });

  it('forwards the tool call to the transport with correct credentials', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier('my-cap-token'), policy: makeManifest() },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: { limit: 10 } });

    expect(handler).toHaveBeenCalledTimes(1);
    const [req, creds] = handler.mock.calls[0]!;
    expect(req.tool).toBe('db:read');
    expect(req.args).toEqual({ limit: 10 });
    expect(creds.capabilityToken).toBe('my-cap-token');
    expect(creds.agentId).toBe('agent-guard-test');
  });

  it('also allows a tool listed in optionalCapabilities', async () => {
    const handler = successHandler({ hit: true });
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'cache:read', args: { key: 'k1' } });

    expect(result.guardResult).toBe('allow');
    expect(result.success).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('does NOT invoke onDeny when the guard allows the call', async () => {
    const onDeny = jest.fn();
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest(), onDeny },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(onDeny).not.toHaveBeenCalled();
  });

  it('calls the token supplier once per invocation', async () => {
    let callCount = 0;
    const supplier = () => {
      callCount += 1;
      return `token-${callCount}`;
    };
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard({ tokenSupplier: supplier, policy: makeManifest() }, transport);

    await guard.invokeTool({ tool: 'db:read', args: {} });
    await guard.invokeTool({ tool: 'storage:read', args: {} });

    expect(callCount).toBe(2);
  });

  it('supports an async token supplier', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: async () => 'async-token', policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(result.guardResult).toBe('allow');
    const creds = handler.mock.calls[0]![1];
    expect(creds.capabilityToken).toBe('async-token');
  });

  it('passes the resource field to the transport when provided', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: {}, resource: 'specific-resource' });

    const [req] = handler.mock.calls[0]!;
    expect(req.resource).toBe('specific-resource');
  });
});

// ── 2. Guard denies an out-of-scope tool call ─────────────────────────────────

describe('createAgtGuard — deny out-of-scope tool calls', () => {
  it('returns guardResult "deny" for a tool not in the manifest', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'admin:delete', args: {} });

    expect(result.guardResult).toBe('deny');
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
    expect(result.denyReason).toBe('capability_not_found');
  });

  it('does NOT invoke the transport when the guard denies', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    await guard.invokeTool({ tool: 'root:exec', args: {} });

    expect(handler).not.toHaveBeenCalled();
  });

  it('invokes onDeny with the tool name and reason "capability_not_found"', async () => {
    const denials: Array<{ tool: string; reason: AgtGuardDenyReason }> = [];
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onDeny: (tool, reason) => denials.push({ tool, reason }),
      },
      transport,
    );

    await guard.invokeTool({ tool: 'unlisted:tool', args: {} });

    expect(denials).toHaveLength(1);
    expect(denials[0]).toEqual({ tool: 'unlisted:tool', reason: 'capability_not_found' });
  });

  it('does NOT invoke onGatewayDeny when the guard itself blocks the call', async () => {
    const onGatewayDeny = jest.fn();
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest(), onGatewayDeny },
      transport,
    );

    await guard.invokeTool({ tool: 'not:listed', args: {} });

    expect(onGatewayDeny).not.toHaveBeenCalled();
  });

  it('uses the error message that embeds the deny reason', async () => {
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'missing', args: {} });

    expect(result.error).toContain('capability_not_found');
  });

  it('fails closed (policy_evaluation_error) when token supplier throws', async () => {
    const onDeny = jest.fn();
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard(
      {
        tokenSupplier: () => { throw new Error('supplier failed'); },
        policy: makeManifest(),
        onDeny,
      },
      transport,
    );

    // 'db:read' is in scope, so the guard will attempt token acquisition.
    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(result.guardResult).toBe('deny');
    expect(result.denyReason).toBe('policy_evaluation_error');
    expect(onDeny).toHaveBeenCalledWith('db:read', 'policy_evaluation_error');
  });

  it('swallows exceptions thrown by the onDeny callback', async () => {
    const transport = new InProcessToolTransport(successHandler());
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onDeny: () => { throw new Error('callback error'); },
      },
      transport,
    );

    // Should not throw even though onDeny throws.
    await expect(
      guard.invokeTool({ tool: 'unknown', args: {} }),
    ).resolves.toMatchObject({ guardResult: 'deny' });
  });
});

// ── 3. Guard allows but gateway denies ───────────────────────────────────────

describe('createAgtGuard — guard allow, gateway deny', () => {
  it('invokes onGatewayDeny with tool name and errorCode when gateway returns 403', async () => {
    const gatewayDenials: Array<{ tool: string; code: string }> = [];
    const handler = gatewayDenyHandler(403, 'CAPABILITY_DENIED');
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onGatewayDeny: (tool, code) => gatewayDenials.push({ tool, code }),
      },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    // Guard itself allowed (guardResult = 'allow'); gateway denied (success = false).
    expect(result.guardResult).toBe('allow');
    expect(result.success).toBe(false);
    expect(result.statusCode).toBe(403);
    expect(result.denyReason).toBeUndefined();

    expect(gatewayDenials).toHaveLength(1);
    expect(gatewayDenials[0]).toEqual({ tool: 'db:read', code: 'CAPABILITY_DENIED' });
  });

  it('does NOT invoke onDeny when the gateway denies a guard-allowed call', async () => {
    const onDeny = jest.fn();
    const transport = new InProcessToolTransport(gatewayDenyHandler(401, 'EXPIRED_TOKEN'));
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest(), onDeny },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(onDeny).not.toHaveBeenCalled();
  });

  it('uses HTTP status code as fallback errorCode when gateway provides none', async () => {
    const gatewayDenials: Array<{ code: string }> = [];
    const transport = new InProcessToolTransport(gatewayDenyHandler(401));
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onGatewayDeny: (_tool, code) => gatewayDenials.push({ code }),
      },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(gatewayDenials[0]?.code).toBe('HTTP_401');
  });

  it('invokes onGatewayDeny for TOKEN_REVOKED (401)', async () => {
    const denials: string[] = [];
    const transport = new InProcessToolTransport(
      gatewayDenyHandler(401, 'TOKEN_REVOKED'),
    );
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onGatewayDeny: (_tool, code) => denials.push(code),
      },
      transport,
    );

    await guard.invokeTool({ tool: 'storage:read', args: {} });

    expect(denials).toContain('TOKEN_REVOKED');
  });

  it('does not invoke onGatewayDeny for a successful gateway response', async () => {
    const onGatewayDeny = jest.fn();
    const transport = new InProcessToolTransport(successHandler({ data: 'payload' }));
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest(), onGatewayDeny },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(onGatewayDeny).not.toHaveBeenCalled();
  });

  it('swallows exceptions thrown by the onGatewayDeny callback', async () => {
    const transport = new InProcessToolTransport(gatewayDenyHandler(403, 'CAPABILITY_DENIED'));
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onGatewayDeny: () => { throw new Error('observer error'); },
      },
      transport,
    );

    // Should resolve, not throw, even though the callback throws.
    await expect(
      guard.invokeTool({ tool: 'db:read', args: {} }),
    ).resolves.toMatchObject({ guardResult: 'allow', success: false });
  });
});

// ── 4. Integration test — Set-D2 flow (guard → gateway → API) ────────────────

describe('createAgtGuard — Set-D2 integration flow', () => {
  /**
   * Models the full Set-D2 sequence from `docs/diagrams.md`:
   *
   *   Agent → AGT (propose tool action)
   *         AGT checks policy → ALLOW
   *   Agent → Gateway (tool request + capability token)
   *         Gateway validates token → ALLOW
   *   Gateway → API (forward authorized request)
   *         API returns result
   *   Gateway → Agent (result)
   *
   * The gateway and API are both simulated by the InProcessToolTransport
   * handler, which mimics the gateway validating the token and forwarding
   * the request to the (in-process) API.
   */

  it('Set-D2: allowed tool propagates through guard → gateway → API and returns result', async () => {
    const gatewayDenials: string[] = [];
    const guardDenials: string[] = [];

    // Mock "gateway + API": validates the capability token is present, then
    // returns a simulated API response.
    const gatewayAndApi = jest.fn<
      Promise<ToolTransportResponse>,
      [ToolTransportInvokeRequest, TransportCredentials]
    >().mockImplementation(async (req, creds) => {
      if (!creds.capabilityToken) {
        return { success: false, statusCode: 401, error: 'No token', errorCode: 'MISSING_TOKEN' };
      }
      // Simulate the gateway forwarding to the API and returning the result.
      return {
        success: true,
        statusCode: 200,
        data: { tool: req.tool, args: req.args, apiResult: 'database-rows' },
      };
    });

    const transport = new InProcessToolTransport(gatewayAndApi);
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier('jwt.cap.token'),
        policy: makeManifest(),
        onDeny: (tool) => guardDenials.push(tool),
        onGatewayDeny: (tool) => gatewayDenials.push(tool),
      },
      transport,
    );

    // Step 1 — AGT evaluates the proposed action.
    const response = await guard.invokeTool({
      tool: 'db:read',
      args: { table: 'users', limit: 5 },
    });

    // Step 2 — The guard allowed the call.
    expect(response.guardResult).toBe('allow');
    // Step 3 — The gateway (transport mock) accepted the token and returned 200.
    expect(response.success).toBe(true);
    expect(response.statusCode).toBe(200);
    // Step 4 — The API result is available.
    expect((response.data as Record<string, unknown>)['apiResult']).toBe('database-rows');
    // Neither callback was invoked.
    expect(guardDenials).toHaveLength(0);
    expect(gatewayDenials).toHaveLength(0);
    // The gateway received the correct capability token.
    const receivedCreds = gatewayAndApi.mock.calls[0]![1];
    expect(receivedCreds.capabilityToken).toBe('jwt.cap.token');
    expect(receivedCreds.agentId).toBe('agent-guard-test');
  });

  it('Set-D2 (AGT blocks): AGT blocks out-of-scope action before gateway is reached', async () => {
    const guardDenials: Array<{ tool: string; reason: AgtGuardDenyReason }> = [];
    const gatewayHandler = jest.fn<
      Promise<ToolTransportResponse>,
      [ToolTransportInvokeRequest, TransportCredentials]
    >();

    const transport = new InProcessToolTransport(gatewayHandler);
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest(),
        onDeny: (tool, reason) => guardDenials.push({ tool, reason }),
      },
      transport,
    );

    // Try to invoke a tool not in the manifest.
    const response = await guard.invokeTool({
      tool: 'system:shutdown',
      args: {},
    });

    // AGT blocked the call.
    expect(response.guardResult).toBe('deny');
    expect(response.success).toBe(false);
    expect(response.denyReason).toBe('capability_not_found');
    // Gateway (transport) was never called — the guard is the sole denial record here.
    expect(gatewayHandler).not.toHaveBeenCalled();
    // onDeny was invoked with the correct details.
    expect(guardDenials).toHaveLength(1);
    expect(guardDenials[0]).toEqual({
      tool: 'system:shutdown',
      reason: 'capability_not_found',
    });
  });

  it('Set-D2 (gateway blocks): guard allows but stale token is rejected by gateway', async () => {
    const gatewayDenials: Array<{ tool: string; code: string }> = [];
    const guardDenials: string[] = [];

    // Simulate the gateway detecting an expired token.
    const gatewayRejectsExpiredToken = jest.fn<
      Promise<ToolTransportResponse>,
      [ToolTransportInvokeRequest, TransportCredentials]
    >().mockResolvedValue({
      success: false,
      statusCode: 401,
      error: 'Token has expired',
      errorCode: 'EXPIRED_TOKEN',
    });

    const transport = new InProcessToolTransport(gatewayRejectsExpiredToken);
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier('stale-token'),
        policy: makeManifest(),
        onDeny: (tool) => guardDenials.push(tool),
        onGatewayDeny: (tool, code) => gatewayDenials.push({ tool, code }),
      },
      transport,
    );

    const response = await guard.invokeTool({ tool: 'storage:read', args: {} });

    // Guard itself allowed the call (it doesn't validate token expiry).
    expect(response.guardResult).toBe('allow');
    // Gateway denied (hard enforcement).
    expect(response.success).toBe(false);
    expect(response.errorCode).toBe('EXPIRED_TOKEN');
    // onGatewayDeny is the sole signal; onDeny was NOT invoked.
    expect(gatewayDenials).toHaveLength(1);
    expect(gatewayDenials[0]).toEqual({ tool: 'storage:read', code: 'EXPIRED_TOKEN' });
    expect(guardDenials).toHaveLength(0);
  });

  it('Set-D2 (multiple invocations): guard processes sequential tool calls independently', async () => {
    const handler = jest.fn<
      Promise<ToolTransportResponse>,
      [ToolTransportInvokeRequest, TransportCredentials]
    >()
      .mockResolvedValueOnce({ success: true, statusCode: 200, data: { call: 1 } })
      .mockResolvedValueOnce({ success: true, statusCode: 200, data: { call: 2 } });

    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const r1 = await guard.invokeTool({ tool: 'db:read', args: { seq: 1 } });
    const r2 = await guard.invokeTool({ tool: 'storage:read', args: { seq: 2 } });

    expect(r1.guardResult).toBe('allow');
    expect(r2.guardResult).toBe('allow');
    expect((r1.data as Record<string, unknown>)['call']).toBe(1);
    expect((r2.data as Record<string, unknown>)['call']).toBe(2);
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('Set-D2: guard with no onDeny/onGatewayDeny callbacks still functions correctly', async () => {
    const transport = new InProcessToolTransport(
      jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>()
        .mockResolvedValue({ success: true, statusCode: 200, data: {} }),
    );
    // No callbacks provided — should not throw.
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const allowed = await guard.invokeTool({ tool: 'db:read', args: {} });
    const denied = await guard.invokeTool({ tool: 'unlisted', args: {} });

    expect(allowed.guardResult).toBe('allow');
    expect(denied.guardResult).toBe('deny');
  });
});

// ── Edge cases ────────────────────────────────────────────────────────────────

describe('createAgtGuard — edge cases', () => {
  it('returns the full transport response data on success', async () => {
    const transport = new InProcessToolTransport(
      jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>()
        .mockResolvedValue({ success: true, statusCode: 200, data: { count: 42 } }),
    );
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(result.data).toEqual({ count: 42 });
  });

  it('guard with empty requiredCapabilities denies all tool calls', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest({ requiredCapabilities: [], optionalCapabilities: [] }),
      },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(result.guardResult).toBe('deny');
    expect(result.denyReason).toBe('capability_not_found');
    expect(handler).not.toHaveBeenCalled();
  });

  it('guard result contains the transport errorCode on gateway deny', async () => {
    const transport = new InProcessToolTransport(
      gatewayDenyHandler(403, 'AGENT_TERMINATED'),
    );
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(result.errorCode).toBe('AGENT_TERMINATED');
  });

  it('preserves the original transport response body on gateway deny', async () => {
    const gatewayBody = { error: { code: 'CAPABILITY_DENIED', message: 'not in scope' } };
    const transport = new InProcessToolTransport(
      jest.fn<Promise<ToolTransportResponse>, [ToolTransportInvokeRequest, TransportCredentials]>()
        .mockResolvedValue({
          success: false,
          statusCode: 403,
          data: gatewayBody,
          errorCode: 'CAPABILITY_DENIED',
        }),
    );
    const guard = createAgtGuard(
      { tokenSupplier: staticSupplier(), policy: makeManifest() },
      transport,
    );

    const result = await guard.invokeTool({ tool: 'db:read', args: {} });

    expect(result.data).toEqual(gatewayBody);
  });

  it('the agentId in credentials is taken from policy.agentId, not a hard-coded value', async () => {
    const handler = successHandler();
    const transport = new InProcessToolTransport(handler);
    const guard = createAgtGuard(
      {
        tokenSupplier: staticSupplier(),
        policy: makeManifest({ agentId: 'custom-agent-id' }),
      },
      transport,
    );

    await guard.invokeTool({ tool: 'db:read', args: {} });

    const creds = handler.mock.calls[0]![1];
    expect(creds.agentId).toBe('custom-agent-id');
  });
});
