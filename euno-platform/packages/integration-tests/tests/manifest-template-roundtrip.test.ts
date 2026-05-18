import * as http from 'http';
import express, { NextFunction, Request, Response as ExpressResponse } from 'express';
import {
  AgentCapabilityManifest,
  CapabilityConstraint,
  CapabilityError,
  CapabilityTokenPayload,
  ErrorCode,
  IdentityAdapter,
  IdentityAdapterConfig,
  IssueCapabilityRequest,
  IssuanceContext,
  SigningAdapter,
  SigningAdapterConfig,
  UserContext,
  createLogger,
} from '@euno/common';
import { CapabilityIssuerService } from '../../capability-issuer/src/issuer-service';
import {
  AssignBindingResult,
  ManifestTemplateStore,
  TemplateAssignment,
  TemplateBinding,
  TemplateListItem,
  TemplateRecord,
  TemplateStoreError,
  TemplateVersionRecord,
} from '../../capability-issuer/src/manifest-template-store';
import { createAdminTemplatesRouter } from '../../capability-issuer/src/routes/admin-templates';

const TENANT_ID = 'tenant-acme';
const ADMIN_API_KEY = 'stage4-admin-key';
const ISSUER_DID = 'did:web:issuer.test';
const AGENT_ID = 'agent-crm';

const REQUEST_MANIFEST: AgentCapabilityManifest = {
  agentId: AGENT_ID,
  name: 'Request manifest',
  version: '1.0.0',
  requiredCapabilities: [
    { resource: 'api://crm/customers', actions: ['read', 'write'] },
  ],
};

const TEMPLATE_MANIFEST: AgentCapabilityManifest = {
  agentId: AGENT_ID,
  name: 'Template manifest',
  version: '2.0.0',
  requiredCapabilities: [
    { resource: 'api://crm/customers', actions: ['read'] },
  ],
};

interface RunningServer {
  baseUrl: string;
  close: () => Promise<void>;
}

class StubIdentityProvider extends IdentityAdapter {
  public readonly name = 'stub-identity';

  constructor(private readonly contexts: ReadonlyMap<string, UserContext>) {
    super({ type: 'stub-identity', name: 'stub-identity' } as IdentityAdapterConfig);
  }

  async validateToken(token: string): Promise<UserContext> {
    const context = this.contexts.get(token);
    if (!context) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Unknown test auth token',
        401,
      );
    }
    return context;
  }

  async getUserRoles(userId: string): Promise<string[]> {
    for (const context of this.contexts.values()) {
      if (context.userId === userId) return context.roles;
    }
    return [];
  }
}

class StubSigner extends SigningAdapter {
  constructor() {
    super({ type: 'stub-signer', name: 'stub-signer', algorithm: 'RS256' } as SigningAdapterConfig);
  }

  async sign(payload: CapabilityTokenPayload, _context?: IssuanceContext): Promise<string> {
    return `stub.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;
  }

  async getPublicKey(): Promise<string> {
    return '-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----';
  }

  async getKeyId(): Promise<string> {
    return 'stub-key-id';
  }
}

class InMemoryTemplateStore implements ManifestTemplateStore {
  private readonly templates = new Map<
    string,
    {
      record: TemplateRecord;
      versions: TemplateVersionRecord[];
      assignments: TemplateAssignment[];
    }
  >();
  private nextTemplateId = 1;
  private nextAssignmentId = 1;

  async createTemplate(
    input: {
      ownerTenantId: string;
      name: string;
      manifest: AgentCapabilityManifest;
      createdBy: string;
    },
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord }> {
    for (const template of this.templates.values()) {
      if (
        template.record.ownerTenantId === input.ownerTenantId &&
        template.record.name === input.name &&
        template.record.deletedAt === null
      ) {
        throw new TemplateStoreError('CONFLICT', 'template already exists');
      }
    }

    const templateId = `tmpl_${this.nextTemplateId++}`;
    const createdAt = new Date().toISOString();
    const record: TemplateRecord = {
      templateId,
      ownerTenantId: input.ownerTenantId,
      name: input.name,
      createdBy: input.createdBy,
      createdAt,
      deletedAt: null,
    };
    const version: TemplateVersionRecord = {
      templateId,
      version: 1,
      manifest: input.manifest,
      policyHash: this.hashManifest(input.manifest),
      createdBy: input.createdBy,
      createdAt,
    };

    this.templates.set(templateId, { record, versions: [version], assignments: [] });
    return { record, version };
  }

  async listTemplates(
    ownerTenantId: string,
    _opts?: { cursor?: string; limit?: number; includeDeleted?: boolean },
  ): Promise<{ items: TemplateListItem[]; nextCursor: string | null }> {
    const items = Array.from(this.templates.values())
      .filter((template) => template.record.ownerTenantId === ownerTenantId)
      .filter((template) => template.record.deletedAt === null)
      .map((template) => {
        const latest = template.versions[template.versions.length - 1]!;
        return {
          ...template.record,
          latestVersion: latest.version,
          policyHash: latest.policyHash,
        };
      });
    return { items, nextCursor: null };
  }

  async getTemplate(
    templateId: string,
    ownerTenantId: string,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord } | undefined> {
    const template = this.templates.get(templateId);
    if (!template || template.record.ownerTenantId !== ownerTenantId) return undefined;
    return { record: template.record, version: template.versions[template.versions.length - 1]! };
  }

  async getTemplateVersion(
    templateId: string,
    version: number,
    ownerTenantId: string,
  ): Promise<{ record: TemplateRecord; version: TemplateVersionRecord } | undefined> {
    const template = this.templates.get(templateId);
    if (!template || template.record.ownerTenantId !== ownerTenantId) return undefined;
    const found = template.versions.find((candidate) => candidate.version === version);
    return found ? { record: template.record, version: found } : undefined;
  }

  async appendVersion(
    input: {
      templateId: string;
      ownerTenantId: string;
      manifest: AgentCapabilityManifest;
      createdBy: string;
    },
  ): Promise<TemplateVersionRecord> {
    const template = this.requireTemplate(input.templateId, input.ownerTenantId);
    const createdAt = new Date().toISOString();
    const version: TemplateVersionRecord = {
      templateId: input.templateId,
      version: template.versions[template.versions.length - 1]!.version + 1,
      manifest: input.manifest,
      policyHash: this.hashManifest(input.manifest),
      createdBy: input.createdBy,
      createdAt,
    };
    template.versions.push(version);
    return version;
  }

  async assignTemplate(
    templateId: string,
    ownerTenantId: string,
    bindings: TemplateBinding[],
    assignedBy: string,
  ): Promise<AssignBindingResult[]> {
    const template = this.requireTemplate(templateId, ownerTenantId);
    const latestVersion = template.versions[template.versions.length - 1]!;

    return bindings.map((binding) => {
      const existing = template.assignments.find(
        (assignment) =>
          assignment.tenantId === binding.tenantId &&
          assignment.agentId === binding.agentId &&
          assignment.role === binding.role &&
          assignment.revokedAt === null,
      );
      if (existing) {
        return { kind: 'skipped', reason: 'already_assigned' } as const;
      }

      const assignmentId = `asg_${this.nextAssignmentId++}`;
      template.assignments.push({
        assignmentId,
        templateId,
        templateVersion: binding.version ?? latestVersion.version,
        tenantId: binding.tenantId,
        agentId: binding.agentId,
        role: binding.role,
        assignedBy,
        assignedAt: new Date().toISOString(),
        revokedAt: null,
      });
      return {
        kind: 'created',
        assignmentId,
        version: binding.version ?? latestVersion.version,
      } as const;
    });
  }

  async softDelete(templateId: string, ownerTenantId: string): Promise<string | undefined> {
    const template = this.templates.get(templateId);
    if (!template || template.record.ownerTenantId !== ownerTenantId) return undefined;
    if (template.record.deletedAt !== null) {
      throw new TemplateStoreError('ALREADY_DELETED', 'template already deleted');
    }
    template.record.deletedAt = new Date().toISOString();
    return template.record.deletedAt;
  }

  async findActiveAssignment(
    tenantId: string,
    agentId: string,
    role: string,
  ): Promise<
    | {
        templateId: string;
        version: number;
        manifest: AgentCapabilityManifest;
        policyHash: string;
      }
    | undefined
  > {
    for (const template of this.templates.values()) {
      const assignment = template.assignments.find(
        (candidate) =>
          candidate.tenantId === tenantId &&
          candidate.agentId === agentId &&
          candidate.role === role &&
          candidate.revokedAt === null &&
          template.record.deletedAt === null,
      );
      if (!assignment) continue;
      const version = template.versions.find(
        (candidate) => candidate.version === assignment.templateVersion,
      );
      if (!version) continue;
      return {
        templateId: assignment.templateId,
        version: assignment.templateVersion,
        manifest: version.manifest,
        policyHash: version.policyHash,
      };
    }
    return undefined;
  }

  private requireTemplate(
    templateId: string,
    ownerTenantId: string,
  ): {
    record: TemplateRecord;
    versions: TemplateVersionRecord[];
    assignments: TemplateAssignment[];
  } {
    const template = this.templates.get(templateId);
    if (!template || template.record.ownerTenantId !== ownerTenantId) {
      throw new TemplateStoreError('NOT_FOUND', 'template not found');
    }
    if (template.record.deletedAt !== null) {
      throw new TemplateStoreError('DELETED', 'template is deleted');
    }
    return template;
  }

  private hashManifest(manifest: AgentCapabilityManifest): string {
    return Buffer.from(JSON.stringify(manifest)).toString('base64url');
  }
}

async function startServer(
  service: CapabilityIssuerService,
  store: ManifestTemplateStore,
): Promise<RunningServer> {
  const logger = createLogger('manifest-template-roundtrip', 'test');
  const app = express();
  app.use(express.json());
  app.use(
    '/api/v1/admin/templates',
    createAdminTemplatesRouter({
      store,
      adminApiKey: ADMIN_API_KEY,
      logger,
    }),
  );

  app.get('/admin/templates', (_req, res) => {
    res.status(200).send('<html><body>templates</body></html>');
  });

  app.post('/api/v1/issue', async (req: Request, res: ExpressResponse, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      const authToken =
        typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')
          ? authHeader.slice('bearer '.length).trim()
          : '';
      if (authToken.length === 0) {
        throw new CapabilityError(
          ErrorCode.AUTHENTICATION_FAILED,
          'Authorization header with Bearer token is required',
          401,
        );
      }

      const issueRequest: IssueCapabilityRequest = {
        authToken,
        agentId: req.body.agentId,
        manifest: req.body.manifest,
      };

      const response = await service.issueCapability(issueRequest);
      res.json(response);
    } catch (error) {
      next(error);
    }
  });

  app.use(
    (error: unknown, _req: Request, res: ExpressResponse, _next: NextFunction) => {
      if (error instanceof CapabilityError) {
        res.status(error.statusCode).json({ error: error.message, code: error.code });
        return;
      }
      res.status(500).json({
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    },
  );

  const server = await new Promise<http.Server>((resolve) => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to determine test server address');
  }
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    }),
  };
}

function decodePayload(token: string): Record<string, unknown> {
  const payloadSegment = token.split('.')[1];
  if (!payloadSegment) {
    throw new Error('Token payload segment missing');
  }
  return JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

async function postJson(
  baseUrl: string,
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

describe('manifest template round-trip integration (E4)', () => {
  const userContexts = new Map<string, UserContext>([
    [
      'viewer-token',
      {
        userId: 'user-1',
        email: 'viewer@example.com',
        roles: ['Viewer'],
        tenantId: TENANT_ID,
        claims: {},
      },
    ],
    [
      'admin-token',
      {
        userId: 'user-2',
        email: 'admin@example.com',
        roles: ['Administrator'],
        tenantId: TENANT_ID,
        claims: {},
      },
    ],
  ]);

  let server: RunningServer;

  beforeEach(async () => {
    const store = new InMemoryTemplateStore();
    const service = new CapabilityIssuerService(
      new StubSigner(),
      new StubIdentityProvider(userContexts),
      ISSUER_DID,
      900,
      createLogger('manifest-template-roundtrip', 'test'),
      { templateStore: store },
    );
    server = await startServer(service, store);
  });

  afterEach(async () => {
    await server.close();
  });

  it('round-trips list → create → assign → issuance using the issuer admin API', async () => {
    const initialList = await fetch(
      `${server.baseUrl}/api/v1/admin/templates?ownerTenantId=${encodeURIComponent(TENANT_ID)}`,
      { headers: { 'x-admin-key': ADMIN_API_KEY } },
    );
    expect(initialList.status).toBe(200);
    const initialBody = await initialList.json() as { items: unknown[] };
    expect(initialBody.items).toEqual([]);

    const createResponse = await postJson(
      server.baseUrl,
      '/api/v1/admin/templates',
      {
        ownerTenantId: TENANT_ID,
        name: 'CRM template',
        manifest: TEMPLATE_MANIFEST,
      },
      { 'x-admin-key': ADMIN_API_KEY },
    );
    expect(createResponse.status).toBe(201);
    const created = await createResponse.json() as unknown as { templateId: string };

    const assignResponse = await postJson(
      server.baseUrl,
      `/api/v1/admin/templates/${encodeURIComponent(created.templateId)}/assign`,
      {
        ownerTenantId: TENANT_ID,
        bindings: [{ tenantId: TENANT_ID, agentId: AGENT_ID, role: 'Viewer' }],
      },
      { 'x-admin-key': ADMIN_API_KEY },
    );
    expect(assignResponse.status).toBe(200);
    const assigned = await assignResponse.json() as unknown as { created: Array<{ role: string }> };
    expect(assigned.created).toHaveLength(1);
    expect(assigned.created[0]?.role).toBe('Viewer');

    const issueResponse = await postJson(
      server.baseUrl,
      '/api/v1/issue',
      {
        agentId: AGENT_ID,
        manifest: REQUEST_MANIFEST,
      },
      { authorization: 'Bearer viewer-token' },
    );
    expect(issueResponse.status).toBe(200);
    const issued = await issueResponse.json() as unknown as {
      token: string;
      capabilities: CapabilityConstraint[];
    };
    expect(issued.capabilities).toEqual(TEMPLATE_MANIFEST.requiredCapabilities);

    const payload = decodePayload(issued.token);
    expect(payload.capabilities).toEqual(TEMPLATE_MANIFEST.requiredCapabilities);
    expect((payload.vc as { credentialSubject?: { capabilities?: CapabilityConstraint[] } }).credentialSubject?.capabilities)
      .toEqual(TEMPLATE_MANIFEST.requiredCapabilities);
  });

  it('falls back to the request manifest when no template assignment exists', async () => {
    const issueResponse = await postJson(
      server.baseUrl,
      '/api/v1/issue',
      {
        agentId: 'agent-without-template',
        manifest: REQUEST_MANIFEST,
      },
      { authorization: 'Bearer admin-token' },
    );
    expect(issueResponse.status).toBe(200);
    const issued = await issueResponse.json() as unknown as {
      token: string;
      capabilities: CapabilityConstraint[];
    };
    expect(issued.capabilities).toEqual(REQUEST_MANIFEST.requiredCapabilities);

    const payload = decodePayload(issued.token);
    expect(payload.capabilities).toEqual(REQUEST_MANIFEST.requiredCapabilities);
  });
});
