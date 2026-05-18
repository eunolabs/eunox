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
 *   - DI-2: ?token= query parameter NO LONGER accepted; session cookie flow tested
 *   - DI-2: POST /admin/auth/session exchanges JWT for HttpOnly session cookie
 *   - DI-2: DELETE /admin/auth/session clears session cookie
 *   - DI-2: GET /admin/login serves login page without auth
 *   - DI-2: Session cookie accepted as auth for page routes
 *   - CI-4: Dynamic templateId values are safeJsonEmbed'd in script contexts
 *   - Page-level access control: unauthenticated requests to each page return 401
 */

import express from 'express';
import request from 'supertest';
import { createLogger } from '@euno/common';
import type { ManifestTemplateStore } from '../src/manifest-template-store';
import { createAdminUiRouter, SESSION_COOKIE_NAME } from '../src/routes/admin-ui';
import type { CapabilityError } from '@euno/common';
import type { IssuerAdminJwtVerifier } from '../src/routes/admin-templates';

// ── Minimal stub template store ─────────────────────────────────────────────

const STUB_MANIFEST = {
  agentId: 'agent-test',
  name: 'Test Agent',
  version: '0.1.0',
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

/** Stub JWT verifier that accepts the single VALID_JWT constant as valid. */
const VALID_JWT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.stub-payload.stub-sig';

const stubJwtVerifier = {
  async verify(token: string) {
    if (token === VALID_JWT) {
      return { operatorId: 'op-test', tenantId: 'tenant-test', isPlatformAdmin: true };
    }
    throw new Error('Invalid token');
  },
} as unknown as IssuerAdminJwtVerifier;

function buildUiTestApp(
  store: ManifestTemplateStore = new StubTemplateStore(),
  jwtVerifier?: IssuerAdminJwtVerifier,
) {
  const app = express();
  app.use(express.json());

  const logger = createLogger('test', 'test');
  const router = createAdminUiRouter({
    store,
    adminApiKey: ADMIN_KEY,
    jwtVerifier,
    logger,
    // Disable Secure attribute so tests run on HTTP without errors.
    secureCookies: false,
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

  it('list page does NOT reference localStorage or ?token= (DI-2)', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    // DI-2: token must never be written to URL or localStorage
    expect(res.text).not.toContain('localStorage.setItem');
    expect(res.text).not.toContain('localStorage.getItem');
    expect(res.text).not.toContain('?token=');
    expect(res.text).not.toContain("qs.get('token')");
  });

  it('list page does NOT accept ?token= query parameter (DI-2 — removed)', async () => {
    // The ?token= query param path has been removed as part of DI-2.
    // The page should still render (auth is via X-Admin-Key header here)
    // but the page HTML must not contain the old localStorage ?token= logic.
    const res = await request(app)
      .get('/admin/templates?token=some-future-jwt')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    // No localStorage usage
    expect(res.text).not.toContain('localStorage.setItem');
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

// ── DI-2: Session cookie exchange ─────────────────────────────────────────────

describe('Admin UI — DI-2: GET /admin/login (no auth required)', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(new StubTemplateStore(), stubJwtVerifier); });

  it('returns 200 HTML without credentials', async () => {
    const res = await request(app).get('/admin/login').expect(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.text).toMatch(/<!DOCTYPE html/i);
  });

  it('contains a token input and sign-in button', async () => {
    const res = await request(app).get('/admin/login').expect(200);
    expect(res.text).toContain('id="login-token"');
    expect(res.text).toContain('btn-login');
  });

  it('login page JS posts to /admin/auth/session (not a URL redirect)', async () => {
    const res = await request(app).get('/admin/login').expect(200);
    expect(res.text).toContain('/admin/auth/session');
    // Must not reference ?token= in any form
    expect(res.text).not.toContain('?token=');
  });
});

describe('Admin UI — DI-2: POST /admin/auth/session', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(new StubTemplateStore(), stubJwtVerifier); });

  it('returns 200 and sets HttpOnly session cookie for valid JWT', async () => {
    const res = await request(app)
      .post('/admin/auth/session')
      .send({ token: VALID_JWT })
      .set('Content-Type', 'application/json')
      .expect(200);
    expect(res.body).toEqual({ ok: true });
    // Set-Cookie header must be present
    const setCookie = res.headers['set-cookie'] as string[] | string | undefined;
    expect(setCookie).toBeDefined();
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : (setCookie ?? '');
    expect(cookieStr).toContain(SESSION_COOKIE_NAME);
    expect(cookieStr).toContain('HttpOnly');
    expect(cookieStr).toContain('SameSite=Strict');
    expect(cookieStr).toContain('Path=/admin');
  });

  it('returns 401 for an invalid JWT', async () => {
    const res = await request(app)
      .post('/admin/auth/session')
      .send({ token: 'bad.token.value' })
      .set('Content-Type', 'application/json')
      .expect(401);
    expect(res.body).toMatchObject({ error: { message: expect.stringContaining('Invalid') } });
  });

  it('returns 400 when token field is missing', async () => {
    const res = await request(app)
      .post('/admin/auth/session')
      .send({})
      .set('Content-Type', 'application/json')
      .expect(400);
    expect(res.body.error.message).toMatch(/token is required/i);
  });

  it('also accepts token via Authorization: Bearer header', async () => {
    const res = await request(app)
      .post('/admin/auth/session')
      .send({})
      .set('Content-Type', 'application/json')
      .set('Authorization', `Bearer ${VALID_JWT}`)
      .expect(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('returns 501 when no jwtVerifier is configured', async () => {
    const appNoJwt = buildUiTestApp(new StubTemplateStore()); // no verifier
    const res = await request(appNoJwt)
      .post('/admin/auth/session')
      .send({ token: VALID_JWT })
      .set('Content-Type', 'application/json')
      .expect(501);
    expect(res.body.error.message).toMatch(/not configured/i);
  });
});

describe('Admin UI — DI-2: DELETE /admin/auth/session (logout)', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(new StubTemplateStore(), stubJwtVerifier); });

  it('returns 200 and clears the session cookie', async () => {
    const res = await request(app)
      .delete('/admin/auth/session')
      .expect(200);
    expect(res.body).toEqual({ ok: true });
    const setCookie = res.headers['set-cookie'] as string[] | string | undefined;
    expect(setCookie).toBeDefined();
    const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : (setCookie ?? '');
    // Max-Age=0 clears the cookie
    expect(cookieStr).toContain('Max-Age=0');
    expect(cookieStr).toContain(SESSION_COOKIE_NAME);
  });
});

describe('Admin UI — DI-2: session cookie auth for page routes', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(new StubTemplateStore(), stubJwtVerifier); });

  it('session cookie authenticates the list page', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('Cookie', `${SESSION_COOKIE_NAME}=${encodeURIComponent(VALID_JWT)}`)
      .expect(200);
    expect(res.text).toMatch(/<!DOCTYPE html/i);
  });

  it('invalid session cookie falls through — returns 401 without X-Admin-Key', async () => {
    await request(app)
      .get('/admin/templates')
      .set('Cookie', `${SESSION_COOKIE_NAME}=bad.cookie.value`)
      .expect(401);
  });

  it('page shell embeds session token server-side (not via localStorage)', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('Cookie', `${SESSION_COOKIE_NAME}=${encodeURIComponent(VALID_JWT)}`)
      .expect(200);
    // Token must be embedded via server-side window.__eunoAdminToken assignment
    expect(res.text).toContain('window.__eunoAdminToken');
    // Must NOT use localStorage.setItem / localStorage.getItem
    expect(res.text).not.toContain('localStorage.setItem');
    expect(res.text).not.toContain('localStorage.getItem');
  });

  it('page shell does NOT expose the token in a ?token= query string', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('Cookie', `${SESSION_COOKIE_NAME}=${encodeURIComponent(VALID_JWT)}`)
      .expect(200);
    expect(res.text).not.toContain('?token=');
  });

  it('401 page links to /admin/login (not to ?token= hint)', async () => {
    const res = await request(app)
      .get('/admin/templates')
      .set('Accept', 'text/html')
      .expect(401);
    expect(res.text).toContain('/admin/login');
    expect(res.text).not.toContain('?token=');
  });
});

// ── CI-4: HTML escaping of dynamic values ─────────────────────────────────────

describe('Admin UI — CI-4: HTML escaping and safe JSON embedding', () => {
  let app: ReturnType<typeof buildUiTestApp>;
  beforeEach(() => { app = buildUiTestApp(new StubTemplateStore(), stubJwtVerifier); });

  it('detail page embeds templateId via safeJsonEmbed, not bare JSON.stringify', async () => {
    // A templateId containing </script> would break out of the script block if
    // it were embedded with a bare JSON.stringify.  The safe embed replaces
    // < and / so the string cannot close the tag.
    const xssId = 'tmpl</script><script>alert(1)//';
    const res = await request(app)
      .get(`/admin/templates/${encodeURIComponent(xssId)}`)
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    // The dangerous sequence must NOT appear verbatim in the output
    expect(res.text).not.toContain('</script><script>alert(1)');
    // Both < and / are escaped: </script> → \u003c\u002fscript\u003e
    expect(res.text).toContain('\\u003c\\u002fscript\\u003e');
  });

  it('assign page embeds templateId via safeJsonEmbed', async () => {
    const xssId = 'tmpl</script><script>alert(2)//';
    const res = await request(app)
      .get(`/admin/templates/${encodeURIComponent(xssId)}/assign`)
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).not.toContain('</script><script>alert(2)');
    expect(res.text).toContain('\\u003c\\u002fscript\\u003e');
  });

  it('page title is HTML-escaped', async () => {
    // pageShell always passes title through escHtml — smoke-test with a normal title
    const res = await request(app)
      .get('/admin/templates')
      .set('X-Admin-Key', ADMIN_KEY)
      .expect(200);
    expect(res.text).toContain('<title>Templates — Euno Admin</title>');
  });

  it('server-embedded session token uses safeJsonEmbed (not bare concatenation)', async () => {
    // Use a token that contains '&' so safeJsonEmbed produces \u0026 — which
    // proves the output went through safeJsonEmbed rather than a bare string concat.
    const tokenWithAmpersand = 'eyJhbGciOiJSUzI1NiJ9.with&ampersand.sig';
    const app2 = buildUiTestApp(new StubTemplateStore(), {
      async verify(t: string) {
        if (t === tokenWithAmpersand) {
          return { operatorId: 'op', tenantId: 'ten', isPlatformAdmin: true };
        }
        throw new Error('Invalid');
      },
    } as unknown as IssuerAdminJwtVerifier);
    const res = await request(app2)
      .get('/admin/templates')
      .set('Cookie', `${SESSION_COOKIE_NAME}=${encodeURIComponent(tokenWithAmpersand)}`)
      .expect(200);
    // The '&' in the token must have been escaped to \u0026 by safeJsonEmbed
    expect(res.text).toContain('\\u0026');
    // The raw '&' must NOT appear inside the window.__eunoAdminToken assignment
    expect(res.text).not.toMatch(/window\.__eunoAdminToken\s*=\s*"[^"]*&[^"]*"/);
  });
});

