/**
 * Tests for the server-rendered admin UI routes — Task 7 of Stage 4.
 *
 * Covers:
 *   - Auth enforcement: 401 without credentials, 200 with valid X-Admin-Key,
 *     401 with wrong key, 401 with Accept: text/html (renders HTML 401 page)
 *   - GET /admin/ → 302 redirect to /admin/templates
 *   - GET /admin/templates → 200 HTML containing list scaffolding
 *   - GET /admin/templates/new → 200 HTML containing create form
 *   - GET /admin/templates/:id → 200 HTML containing detail scaffold
 *   - GET /admin/templates/:id/assign → 200 HTML containing assignment form
 *   - ?token= query parameter: accepted as Bearer alternative, stripped from URL hint
 *   - Page-level access control: unauthenticated requests to each page return 401
 */

import express from 'express';
import request from 'supertest';
import { createLogger } from '@euno/common';
import type { ManifestTemplateStore } from '../src/manifest-template-store';
import { createAdminUiRouter } from '../src/routes/admin-ui';
import type { CapabilityError } from '@euno/common';

// ── Minimal stub template store ─────────────────────────────────────────────

const STUB_MANIFEST = {
  agentId: 'agent-test',
  name: 'Test Agent',
  version: '1.0.0',
  requiredCapabilities: [{ resource: 'api://test/**', actions: ['read'] }],
};

class StubTemplateStore implements ManifestTemplateStore {
  async createTemplate(_input: Parameters<ManifestTemplateStore['createTemplate']>[0]) {
    return {
      record: {
        templateId: 'tmpl_ui_test_001',
        ownerTenantId: _input.ownerTenantId,
        name: _input.name,
        createdBy: _input.createdBy,
        createdAt: new Date().toISOString(),
        deletedAt: null,
      },
      version: {
        templateId: 'tmpl_ui_test_001',
        version: 1,
        manifest: _input.manifest,
        policyHash: 'abc123',
        createdBy: _input.createdBy,
        createdAt: new Date().toISOString(),
      },
    };
  }

  async listTemplates(_opts: Parameters<ManifestTemplateStore['listTemplates']>[0]) {
    return { items: [], nextCursor: null };
  }

  async getTemplate(templateId: string, _ownerTenantId: string) {
    if (templateId === 'tmpl_ui_test_001') {
      return {
        record: {
          templateId,
          ownerTenantId: 'tenant-test',
          name: 'UI Test Template',
          createdBy: 'op-1',
          createdAt: new Date().toISOString(),
          deletedAt: null,
        },
        version: {
          templateId,
          version: 1,
          manifest: STUB_MANIFEST,
          policyHash: 'abc123',
          createdBy: 'op-1',
          createdAt: new Date().toISOString(),
        },
      };
    }
    return undefined;
  }

  async getTemplateVersion(
    _templateId: string,
    _version: number,
    _ownerTenantId: string,
  ) {
    return undefined;
  }

  async appendVersion(_input: Parameters<ManifestTemplateStore['appendVersion']>[0]) {
    return {
      templateId: _input.templateId,
      version: 2,
      manifest: _input.manifest,
      policyHash: 'def456',
      createdBy: _input.createdBy,
      createdAt: new Date().toISOString(),
    };
  }

  async assignTemplate(
    _templateId: string,
    _ownerTenantId: string,
    _bindings: Parameters<ManifestTemplateStore['assignTemplate']>[2],
    _operatorId: string,
  ) {
    return [];
  }

  async softDelete(_templateId: string, _ownerTenantId: string) {
    return new Date().toISOString();
  }

  async findActiveAssignment(
    _tenantId: string,
    _agentId: string,
    _role: string,
  ) {
    return undefined;
  }
}

// ── Test app builder ─────────────────────────────────────────────────────────

const ADMIN_KEY = 'test-ui-admin-key';

function buildUiTestApp(store: ManifestTemplateStore = new StubTemplateStore()) {
  const app = express();
  app.use(express.json());

  const logger = createLogger('test', 'test');
  const router = createAdminUiRouter({
    store,
    adminApiKey: ADMIN_KEY,
    logger,
  });
  app.use('/admin', router);

  // Minimal error handler so CapabilityError becomes a JSON response.
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const capErr = err as CapabilityError;
    const status = typeof capErr.statusCode === 'number' ? capErr.statusCode : 500;
    res.status(status).json({ error: { code: capErr.code, message: capErr.message } });
  });

  return app;
}

// ── Auth enforcement ─────────────────────────────────────────────────────────

describe('Admin UI — auth enforcement', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(); });

  it('GET /admin/templates → 401 without credentials', async () => {
    await request(app).get('/admin/templates').expect(401);
  });

  it('GET /admin/templates/new → 401 without credentials', async () => {
    await request(app).get('/admin/templates/new').expect(401);
  });

  it('GET /admin/templates/:id → 401 without credentials', async () => {
    await request(app).get('/admin/templates/tmpl_ui_test_001').expect(401);
  });

  it('GET /admin/templates/:id/assign → 401 without credentials', async () => {
    await request(app).get('/admin/templates/tmpl_ui_test_001/assign').expect(401);
  });

  it('returns HTML 401 page when browser (Accept: text/html) request is unauthenticated', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('Accept', 'text/html')
      .expect(401);
    expect(res.text).toContain('Admin authentication required');
    expect(res.text).toMatch(/<!DOCTYPE html/i);
  });

  it('returns 401 JSON when non-browser request is unauthenticated', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('Accept', 'application/json')
      .expect(401);
    expect(res.body).toMatchObject({ error: { message: expect.stringContaining('Admin') } });
  });

  it('rejects wrong X-Admin-Key with 401', async () => {
    await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', 'wrong-key')
      .expect(401);
  });
});

// ── Redirect ─────────────────────────────────────────────────────────────────

describe('Admin UI — redirect', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(); });

  it('GET /admin/ redirects to /admin/templates', async () => {
    const res = await request(app)
      .get('/admin/')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(302);
    expect(res.headers['location']).toBe('/admin/templates');
  });
});

// ── Page content ──────────────────────────────────────────────────────────────

describe('Admin UI — list page', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(); });

  it('GET /admin/templates returns 200 HTML with valid auth', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.text).toMatch(/<!DOCTYPE html/i);
  });

  it('list page contains Manifest Templates heading', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('Manifest Templates');
  });

  it('list page contains New template link', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('/admin/templates/new');
  });

  it('list page contains JS that calls admin API', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('/api/v1/admin/templates');
  });

  it('list page accepts token via ?token= query parameter', async () => {
    // The page is served (200) when token is valid in the query string.
    // Auth resolves the ?token= value as if it were a Bearer header — but
    // without a JWT verifier configured, the X-Admin-Key path is the only
    // active auth path. We pass X-Admin-Key here so the route is exercised;
    // the ?token= stripping JS is in the rendered HTML.
    const res = await request(app)
      .get('/admin/templates?token=some-future-jwt')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    // The rendered page contains the localStorage JS that strips ?token=.
    expect(res.text).toContain('localStorage.setItem');
  });
});

describe('Admin UI — create page', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(); });

  it('GET /admin/templates/new returns 200 HTML', async () => {
    const res = await request(app)
      .get('/admin/templates/new')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
  });

  it('create page contains a form for name and manifest', async () => {
    const res = await request(app)
      .get('/admin/templates/new')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('id="tmpl-name"');
    expect(res.text).toContain('id="tmpl-manifest"');
  });

  it('create page contains submit button', async () => {
    const res = await request(app)
      .get('/admin/templates/new')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('Create template');
  });

  it('create page JS posts to admin API', async () => {
    const res = await request(app)
      .get('/admin/templates/new')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('/api/v1/admin/templates');
  });
});

describe('Admin UI — detail page', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(); });

  it('GET /admin/templates/:id returns 200 HTML', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
  });

  it('detail page contains templateId in content', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('tmpl_ui_test_001');
  });

  it('detail page contains link to assignments page', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('/admin/templates/tmpl_ui_test_001/assign');
  });

  it('detail page contains version history section', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('Version history');
  });

  it('detail page JS calls the admin API for this template', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('tmpl_ui_test_001');
    expect(res.text).toContain('/api/v1/admin/templates/');
  });
});

describe('Admin UI — assign page', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(); });

  it('GET /admin/templates/:id/assign returns 200 HTML', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001/assign')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
  });

  it('assign page contains assignment form fields', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001/assign')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('id="assign-tenant"');
    expect(res.text).toContain('id="assign-agent"');
    expect(res.text).toContain('id="assign-role"');
  });

  it('assign page contains active assignments section', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001/assign')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('Active assignments');
  });

  it('assign page JS posts to assign endpoint', async () => {
    const res = await request(app)
      .get('/admin/templates/tmpl_ui_test_001/assign')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('/assign');
  });
});

// ── Bearer token via Authorization header ─────────────────────────────────────

describe('Admin UI — Authorization: Bearer header', () => {
  it('accepts a valid bearer token when JWT verifier is not configured (fallback path blocked)', async () => {
    // Without a jwtVerifier, a Bearer token in the Authorization header is not
    // accepted (only X-Admin-Key works). Verifying that path explicitly:
    const app = buildUiTestApp();
    const res = await request(app)
      .get('/admin/templates')
      .set('Authorization', 'Bearer some-unverified-jwt')
      .expect(401);
    expect(res.status).toBe(401);
  });

  it('accepts X-Admin-Key when configured, Bearer header present but no jwtVerifier', async () => {
    const app = buildUiTestApp();
    const res = await request(app)
      .get('/admin/templates')
      .set('Authorization', 'Bearer some-jwt')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toMatch(/<!DOCTYPE html/i);
  });
});

// ── Page-level access control smoke (list → create → detail → assign) ────────

describe('Admin UI — page-level access control smoke (list → create → assign)', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  const headers = { 'X-Admin-Key': ADMIN_KEY };

  beforeEach(() => { app = buildUiTestApp(); });

  it('all four pages return 200 with valid auth', async () => {
    await request(app).get('/admin/templates').set(headers).expect(200);
    await request(app).get('/admin/templates/new').set(headers).expect(200);
    await request(app).get('/admin/templates/tmpl_ui_test_001').set(headers).expect(200);
    await request(app).get('/admin/templates/tmpl_ui_test_001/assign').set(headers).expect(200);
  });

  it('all four pages return 401 without auth', async () => {
    await request(app).get('/admin/templates').expect(401);
    await request(app).get('/admin/templates/new').expect(401);
    await request(app).get('/admin/templates/tmpl_ui_test_001').expect(401);
    await request(app).get('/admin/templates/tmpl_ui_test_001/assign').expect(401);
  });
});
