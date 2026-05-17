/**
 * Server-rendered admin UI for manifest templates — Task 7 of Stage 4.
 *
 * Serves four HTML pages under `/admin/` from the issuer's Express process.
 * All pages require the same authentication as the admin API (either an
 * operator JWT via `Authorization: Bearer <token>` or the `X-Admin-Key`
 * shared secret). If authentication fails the handler returns 401 so the
 * JavaScript layer or a browser redirect can surface the login prompt.
 *
 * Pages:
 *   GET /admin/                           → redirect to /admin/templates
 *   GET /admin/templates                  → list templates
 *   GET /admin/templates/new              → create-template form
 *   GET /admin/templates/:id              → detail + version history
 *   GET /admin/templates/:id/assign       → assignment form + active assignments
 *
 * Auth:
 *   The bearer token may be supplied in:
 *     1. `Authorization: Bearer <token>` header (preferred — used by browsers
 *        with localStorage-stored tokens).
 *     2. `?token=<token>` query parameter (initial redirect from IdP; the page
 *        reads this and stores it in localStorage, then strips it from the URL).
 *     3. `X-Admin-Key: <secret>` header (fallback shared-secret path).
 *
 * All data calls go through the existing `/api/v1/admin/templates` API — there
 * are no UI-specific backend endpoints.  The server renders the page shell and
 * the client JavaScript fetches data from the admin API using the stored token.
 */

import * as crypto from 'crypto';
import { Router, Request, Response, NextFunction } from 'express';
import { CapabilityError, ErrorCode, createLogger } from '@euno/common';
import type { ManifestTemplateStore } from '../manifest-template-store';
import type { IssuerAdminJwtVerifier } from './admin-templates';

type Logger = ReturnType<typeof createLogger>;

// ── Options ────────────────────────────────────────────────────────────────

export interface AdminUiRouterOptions {
  /** The manifest template store (required — pages are only served when store is configured). */
  store: ManifestTemplateStore;
  /** Shared admin API key for the X-Admin-Key fallback auth path. */
  adminApiKey: string;
  /** JWT verifier for the primary Bearer token auth path. */
  jwtVerifier?: IssuerAdminJwtVerifier;
  logger: Logger;
  /**
   * The issuer's public base URL, used to construct the admin API endpoint
   * hrefs that client-side JavaScript calls.  Defaults to an empty string so
   * relative paths are used (works when UI and API are on the same origin).
   */
  publicBaseUrl?: string;
}

// ── Auth helper ────────────────────────────────────────────────────────────

interface AuthResult {
  operatorId: string;
  tenantId: string;
  isPlatformAdmin: boolean;
}

/**
 * Create a constant-time X-Admin-Key checker.
 *
 * Pre-computes the HMAC-SHA256 of the configured key at router creation time
 * (NOT per-request) so the per-request comparison is always between two
 * same-length buffers generated with the same hidden key — eliminating any
 * timing oracle while avoiding unnecessary cryptographic work on the hot path.
 *
 * NOTE: adminApiKey is a high-entropy random bearer credential (≥32 chars in
 * production), NOT a user password. HMAC-SHA256 is appropriate here; a KDF
 * (bcrypt/argon2) would add latency without security benefit for random tokens.
 */
function createXAdminKeyChecker(adminApiKey: string): ((provided: string) => boolean) | null {
  if (adminApiKey.length === 0) return null;
  const hmacKey = crypto.randomBytes(32);
  const expectedHash = crypto
    .createHmac('sha256', hmacKey)
    .update(Buffer.from(adminApiKey, 'utf8'))
    .digest();
  return (provided: string): boolean => {
    const providedHash = crypto
      .createHmac('sha256', hmacKey)
      .update(Buffer.from(provided, 'utf8'))
      .digest();
    return crypto.timingSafeEqual(providedHash, expectedHash);
  };
}

async function resolveAuth(
  req: Request,
  checkXAdminKey: ((provided: string) => boolean) | null,
  jwtVerifier?: IssuerAdminJwtVerifier,
): Promise<AuthResult | null> {
  // 1. Try Bearer JWT (from Authorization header or ?token= query param).
  const rawToken =
    (() => {
      const auth = req.headers['authorization'];
      if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
        return auth.slice('bearer '.length).trim();
      }
      return undefined;
    })() ??
    (typeof req.query.token === 'string' && req.query.token ? req.query.token : undefined);

  if (rawToken && jwtVerifier) {
    try {
      const principal = await jwtVerifier.verify(rawToken);
      return {
        operatorId: principal.operatorId,
        tenantId: principal.tenantId,
        isPlatformAdmin: principal.isPlatformAdmin,
      };
    } catch {
      // Fall through to X-Admin-Key path.
    }
  }

  // 2. Try X-Admin-Key shared secret (active only when adminApiKey was configured).
  if (checkXAdminKey) {
    const provided = req.headers['x-admin-key'];
    if (typeof provided === 'string' && checkXAdminKey(provided)) {
      return { operatorId: 'x-admin-key', tenantId: '', isPlatformAdmin: true };
    }
  }

  return null;
}

// ── HTML helpers ───────────────────────────────────────────────────────────

function pageShell(title: string, body: string, scriptExtra = ''): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escHtml(title)} — Euno Admin</title>
  <link rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
    crossorigin="anonymous">
  <style>
    body { background: #f8f9fa; }
    .sidebar { min-height: 100vh; background: #212529; }
    .sidebar a { color: #adb5bd; text-decoration: none; }
    .sidebar a:hover, .sidebar a.active { color: #fff; }
    pre.policy-hash { font-size: .75rem; word-break: break-all; color: #6c757d; }
    .badge-version { font-size: .7rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-dark bg-dark px-4">
  <a class="navbar-brand fw-bold" href="/admin/templates">Euno · Templates</a>
  <span class="navbar-text text-muted small" id="nav-tenant"></span>
</nav>
<div class="container-fluid">
  <div class="row">
    <nav class="col-md-2 d-none d-md-block sidebar py-3 ps-4">
      <ul class="nav flex-column gap-2">
        <li class="nav-item"><a class="nav-link active" href="/admin/templates">All templates</a></li>
        <li class="nav-item"><a class="nav-link" href="/admin/templates/new">+ New template</a></li>
      </ul>
    </nav>
    <main class="col-md-10 ms-sm-auto col-lg-10 px-md-4 py-4">
      <div id="auth-error" class="alert alert-warning d-none">
        Not authenticated. <a href="#" id="auth-help">How to obtain a token</a>.
      </div>
      ${body}
    </main>
  </div>
</div>
<script>
// ── Token management ──────────────────────────────────────────────────────
(function () {
  var qs = new URLSearchParams(window.location.search);
  var qToken = qs.get('token');
  if (qToken) {
    localStorage.setItem('euno_admin_token', qToken);
    qs.delete('token');
    var newUrl = window.location.pathname + (qs.toString() ? '?' + qs.toString() : '');
    history.replaceState({}, '', newUrl);
  }
  var token = localStorage.getItem('euno_admin_token') || '';
  if (!token) {
    document.getElementById('auth-error').classList.remove('d-none');
  }
  // Expose token to page scripts
  window.__eunoAdminToken = token;
  // Show tenant from JWT sub
  if (token) {
    try {
      var parts = token.split('.');
      var p = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
      if (p.tenantId || p.tid) {
        document.getElementById('nav-tenant').textContent = 'tenant: ' + (p.tenantId || p.tid);
      }
    } catch (_) {}
  }
  window.authHeaders = function() {
    return token ? { 'Authorization': 'Bearer ' + token } : {};
  };
})();
</script>
${scriptExtra}
</body>
</html>`;
}

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ── Page: template list ────────────────────────────────────────────────────

function renderListPage(): string {
  const body = `
<div class="d-flex justify-content-between align-items-center mb-4">
  <h2 class="h4 mb-0">Manifest Templates</h2>
  <a href="/admin/templates/new" class="btn btn-primary btn-sm">+ New template</a>
</div>
<div id="list-loading" class="text-muted">Loading…</div>
<div id="list-error" class="alert alert-danger d-none"></div>
<table class="table table-sm table-hover d-none" id="list-table">
  <thead><tr>
    <th>Name</th><th>Template ID</th><th>Latest version</th>
    <th>Created</th><th>Status</th><th></th>
  </tr></thead>
  <tbody id="list-body"></tbody>
</table>
<div id="list-empty" class="text-muted d-none">No templates yet. <a href="/admin/templates/new">Create the first one</a>.</div>
<nav id="list-pagination" class="mt-3 d-none" aria-label="Pagination">
  <button class="btn btn-outline-secondary btn-sm me-2" id="btn-prev" disabled>← Previous</button>
  <button class="btn btn-outline-secondary btn-sm" id="btn-next" disabled>Next →</button>
</nav>`;

  const script = `<script>
(function(){
  var cursor = null, prevCursors = [];
  function fmt(iso) {
    return iso ? new Date(iso).toLocaleString() : '—';
  }
  function load(c) {
    var url = '/api/v1/admin/templates?limit=20' + (c ? '&cursor=' + encodeURIComponent(c) : '');
    fetch(url, { headers: window.authHeaders() })
      .then(function(r){ return r.json(); })
      .then(function(data){
        document.getElementById('list-loading').classList.add('d-none');
        if (data.error) {
          document.getElementById('list-error').textContent = data.error.message || JSON.stringify(data.error);
          document.getElementById('list-error').classList.remove('d-none');
          return;
        }
        var items = data.items || [];
        if (items.length === 0 && !c) {
          document.getElementById('list-empty').classList.remove('d-none');
          return;
        }
        var tbody = document.getElementById('list-body');
        tbody.innerHTML = '';
        items.forEach(function(t){
          var tr = document.createElement('tr');
          tr.innerHTML = '<td><a href="/admin/templates/' + escHtml(t.templateId) + '">' + escHtml(t.name) + '</a></td>'
            + '<td><code class="text-muted small">' + escHtml(t.templateId) + '</code></td>'
            + '<td class="text-center"><span class="badge bg-secondary badge-version">v' + t.latestVersion + '</span></td>'
            + '<td class="text-muted small">' + fmt(t.createdAt) + '</td>'
            + '<td>' + (t.deletedAt ? '<span class="badge bg-danger">deleted</span>' : '<span class="badge bg-success">active</span>') + '</td>'
            + '<td><a href="/admin/templates/' + escHtml(t.templateId) + '/assign" class="btn btn-sm btn-outline-primary">Assign</a>'
            + ' <button class="btn btn-sm btn-outline-danger ms-1" onclick="doDelete(\'' + escHtml(t.templateId) + '\')">Delete</button></td>';
          tbody.appendChild(tr);
        });
        document.getElementById('list-table').classList.remove('d-none');
        cursor = data.nextCursor || null;
        document.getElementById('list-pagination').classList.toggle('d-none', !cursor && prevCursors.length === 0);
        document.getElementById('btn-next').disabled = !cursor;
        document.getElementById('btn-prev').disabled = prevCursors.length === 0;
      })
      .catch(function(e){ document.getElementById('list-loading').textContent = 'Failed to load: ' + e; });
  }
  document.getElementById('btn-next').onclick = function(){
    if (cursor) { prevCursors.push(cursor); load(cursor); }
  };
  document.getElementById('btn-prev').onclick = function(){
    cursor = prevCursors.pop() || null;
    load(prevCursors.length > 0 ? prevCursors[prevCursors.length - 1] : null);
  };
  function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function doDelete(id) {
    if (!confirm('Soft-delete this template? Existing tokens remain valid until expiry.')) return;
    fetch('/api/v1/admin/templates/' + encodeURIComponent(id), { method: 'DELETE', headers: window.authHeaders() })
      .then(function(r){ return r.json(); })
      .then(function(){ load(null); })
      .catch(function(e){ alert('Delete failed: ' + e); });
  }
  load(null);
})();
</script>`;

  return pageShell('Templates', body, script);
}

// ── Page: create template ──────────────────────────────────────────────────

function renderCreatePage(): string {
  const MANIFEST_PLACEHOLDER = JSON.stringify(
    {
      agentId: 'my-agent',
      name: 'My Agent',
      version: '0.1.0',
      requiredCapabilities: [{ resource: 'api://example/**', actions: ['read'] }],
    },
    null,
    2,
  );

  const body = `
<h2 class="h4 mb-4">New Template</h2>
<form id="create-form" novalidate>
  <div class="mb-3">
    <label for="tmpl-name" class="form-label fw-semibold">Template name <span class="text-danger">*</span></label>
    <input type="text" class="form-control" id="tmpl-name" maxlength="255" required
      placeholder="e.g. Sales CRM Read-only v1">
    <div class="invalid-feedback">Name is required (max 255 chars).</div>
  </div>
  <div class="mb-3">
    <label for="tmpl-tenant" class="form-label fw-semibold">Owner tenant ID</label>
    <input type="text" class="form-control" id="tmpl-tenant"
      placeholder="Derived from JWT if left blank">
    <div class="form-text">Leave blank when using operator JWT (tenant is read from the token).</div>
  </div>
  <div class="mb-3">
    <label for="tmpl-manifest" class="form-label fw-semibold">Manifest JSON <span class="text-danger">*</span></label>
    <textarea class="form-control font-monospace" id="tmpl-manifest" rows="12"
      spellcheck="false" required>${escHtml(MANIFEST_PLACEHOLDER)}</textarea>
    <div class="invalid-feedback">Manifest must be valid JSON matching <code>AgentCapabilityManifest</code>.</div>
  </div>
  <div id="create-error" class="alert alert-danger d-none"></div>
  <div id="create-success" class="alert alert-success d-none"></div>
  <button type="submit" class="btn btn-primary">Create template</button>
  <a href="/admin/templates" class="btn btn-outline-secondary ms-2">Cancel</a>
</form>`;

  const script = `<script>
document.getElementById('create-form').addEventListener('submit', function(ev){
  ev.preventDefault();
  var name = document.getElementById('tmpl-name').value.trim();
  var tenant = document.getElementById('tmpl-tenant').value.trim();
  var manifestRaw = document.getElementById('tmpl-manifest').value;
  var errEl = document.getElementById('create-error');
  var okEl = document.getElementById('create-success');
  errEl.classList.add('d-none');
  okEl.classList.add('d-none');
  var manifest;
  try { manifest = JSON.parse(manifestRaw); } catch(e) {
    errEl.textContent = 'Manifest is not valid JSON: ' + e.message;
    errEl.classList.remove('d-none');
    return;
  }
  if (!name) {
    document.getElementById('tmpl-name').classList.add('is-invalid');
    return;
  }
  var body = { name: name, manifest: manifest };
  if (tenant) body.ownerTenantId = tenant;
  fetch('/api/v1/admin/templates', {
    method: 'POST',
    headers: Object.assign({ 'Content-Type': 'application/json' }, window.authHeaders()),
    body: JSON.stringify(body),
  }).then(function(r){ return r.json().then(function(d){ return { ok: r.ok, status: r.status, data: d }; }); })
  .then(function(res){
    if (!res.ok) {
      errEl.textContent = (res.data.error && res.data.error.message) ? res.data.error.message : JSON.stringify(res.data);
      errEl.classList.remove('d-none');
    } else {
      okEl.innerHTML = 'Template created! ID: <strong>' + res.data.templateId + '</strong> &nbsp; '
        + '<a href="/admin/templates/' + encodeURIComponent(res.data.templateId) + '">View</a>';
      okEl.classList.remove('d-none');
    }
  }).catch(function(e){ errEl.textContent = 'Request failed: ' + e; errEl.classList.remove('d-none'); });
});
</script>`;

  return pageShell('New Template', body, script);
}

// ── Page: template detail + version history ────────────────────────────────

function renderDetailPage(templateId: string): string {
  const safeId = encodeURIComponent(templateId);
  const body = `
<div id="detail-loading" class="text-muted">Loading…</div>
<div id="detail-error" class="alert alert-danger d-none"></div>
<div id="detail-content" class="d-none">
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h2 class="h4 mb-1" id="detail-name"></h2>
      <code class="text-muted small" id="detail-id"></code>
    </div>
    <div>
      <a href="/admin/templates/${safeId}/assign" class="btn btn-sm btn-primary me-2">Manage assignments</a>
      <button class="btn btn-sm btn-outline-danger" id="btn-delete">Delete template</button>
    </div>
  </div>

  <div class="row mb-4">
    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-header fw-semibold">Latest manifest</div>
        <div class="card-body p-2">
          <pre id="detail-manifest" class="mb-0" style="font-size:.8rem;max-height:400px;overflow:auto"></pre>
        </div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-header fw-semibold d-flex justify-content-between align-items-center">
          Version history
          <button class="btn btn-sm btn-outline-primary" id="btn-append-version">+ Append version</button>
        </div>
        <div class="card-body p-0">
          <table class="table table-sm mb-0">
            <thead><tr><th>Version</th><th>Policy hash</th><th>Created</th></tr></thead>
            <tbody id="versions-body"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Append-version form (hidden by default) -->
  <div id="append-form-container" class="d-none">
    <div class="card shadow-sm mb-4">
      <div class="card-header fw-semibold">Append new version</div>
      <div class="card-body">
        <label class="form-label fw-semibold">New manifest JSON</label>
        <textarea class="form-control font-monospace" id="new-manifest-json" rows="10" spellcheck="false"></textarea>
        <div id="append-error" class="alert alert-danger mt-2 d-none"></div>
        <div class="mt-2">
          <button class="btn btn-primary btn-sm" id="btn-submit-append">Append version</button>
          <button class="btn btn-outline-secondary btn-sm ms-2" id="btn-cancel-append">Cancel</button>
        </div>
      </div>
    </div>
  </div>
</div>`;

  const script = `<script>
(function(){
  var TID = ${JSON.stringify(templateId)};
  function fmt(iso) { return iso ? new Date(iso).toLocaleString() : '—'; }
  function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  function load() {
    fetch('/api/v1/admin/templates/' + encodeURIComponent(TID), { headers: window.authHeaders() })
      .then(function(r){ return r.json(); })
      .then(function(d){
        document.getElementById('detail-loading').classList.add('d-none');
        if (d.error) {
          document.getElementById('detail-error').textContent = d.error.message || JSON.stringify(d.error);
          document.getElementById('detail-error').classList.remove('d-none');
          return;
        }
        document.getElementById('detail-name').textContent = d.name;
        document.getElementById('detail-id').textContent = d.templateId;
        document.getElementById('detail-manifest').textContent = JSON.stringify(d.manifest, null, 2);
        document.getElementById('new-manifest-json').value = JSON.stringify(d.manifest, null, 2);
        // Load version list
        var tbody = document.getElementById('versions-body');
        tbody.innerHTML = '';
        for (var v = d.version; v >= 1; v--) {
          (function(ver){
            fetch('/api/v1/admin/templates/' + encodeURIComponent(TID) + '/versions/' + ver, { headers: window.authHeaders() })
              .then(function(r){ return r.json(); })
              .then(function(vd){
                if (vd.error) return;
                var tr = document.createElement('tr');
                tr.innerHTML = '<td><span class="badge bg-secondary badge-version">v' + ver + '</span></td>'
                  + '<td><pre class="policy-hash mb-0">' + escHtml((vd.policyHash||'').slice(0,12) + '…') + '</pre></td>'
                  + '<td class="text-muted small">' + fmt(vd.createdAt) + '</td>';
                tbody.insertBefore(tr, tbody.firstChild);
              });
          })(v);
        }
        document.getElementById('detail-content').classList.remove('d-none');
      })
      .catch(function(e){ document.getElementById('detail-loading').textContent = 'Failed: ' + e; });
  }

  document.getElementById('btn-delete').onclick = function(){
    if (!confirm('Soft-delete this template?')) return;
    fetch('/api/v1/admin/templates/' + encodeURIComponent(TID), { method: 'DELETE', headers: window.authHeaders() })
      .then(function(){ window.location.href = '/admin/templates'; });
  };

  document.getElementById('btn-append-version').onclick = function(){
    document.getElementById('append-form-container').classList.remove('d-none');
  };
  document.getElementById('btn-cancel-append').onclick = function(){
    document.getElementById('append-form-container').classList.add('d-none');
  };
  document.getElementById('btn-submit-append').onclick = function(){
    var raw = document.getElementById('new-manifest-json').value;
    var errEl = document.getElementById('append-error');
    errEl.classList.add('d-none');
    var manifest;
    try { manifest = JSON.parse(raw); } catch(e) {
      errEl.textContent = 'Invalid JSON: ' + e.message;
      errEl.classList.remove('d-none');
      return;
    }
    fetch('/api/v1/admin/templates/' + encodeURIComponent(TID) + '/versions', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, window.authHeaders()),
      body: JSON.stringify({ manifest: manifest }),
    }).then(function(r){ return r.json(); })
    .then(function(d){
      if (d.error) { errEl.textContent = d.error.message; errEl.classList.remove('d-none'); return; }
      document.getElementById('append-form-container').classList.add('d-none');
      load();
    });
  };

  load();
})();
</script>`;

  return pageShell('Template Detail', body, script);
}

// ── Page: assignments ──────────────────────────────────────────────────────

function renderAssignPage(templateId: string): string {
  const safeId = encodeURIComponent(templateId);
  const body = `
<div class="d-flex justify-content-between align-items-center mb-3">
  <h2 class="h4 mb-0">Assignments — <a href="/admin/templates/${safeId}" class="text-decoration-none">${escHtml(templateId)}</a></h2>
</div>

<div class="row">
  <div class="col-md-5">
    <div class="card shadow-sm mb-4">
      <div class="card-header fw-semibold">Assign to agents</div>
      <div class="card-body">
        <div class="mb-2">
          <label class="form-label fw-semibold">Tenant ID <span class="text-danger">*</span></label>
          <input type="text" class="form-control form-control-sm" id="assign-tenant" placeholder="tenant-acme">
        </div>
        <div class="mb-2">
          <label class="form-label fw-semibold">Agent ID <span class="text-danger">*</span></label>
          <input type="text" class="form-control form-control-sm" id="assign-agent" placeholder="my-agent">
        </div>
        <div class="mb-2">
          <label class="form-label fw-semibold">Role <span class="text-danger">*</span></label>
          <input type="text" class="form-control form-control-sm" id="assign-role" placeholder="Viewer">
        </div>
        <div class="mb-2">
          <label class="form-label fw-semibold">Version (optional)</label>
          <input type="number" min="1" class="form-control form-control-sm" id="assign-version" placeholder="latest">
        </div>
        <div id="assign-error" class="alert alert-danger mt-2 d-none"></div>
        <div id="assign-success" class="alert alert-success mt-2 d-none"></div>
        <button class="btn btn-primary btn-sm mt-2" id="btn-assign">Assign</button>
      </div>
    </div>
  </div>
  <div class="col-md-7">
    <div class="card shadow-sm">
      <div class="card-header fw-semibold">Active assignments</div>
      <div id="assign-loading" class="card-body text-muted">Loading…</div>
      <table class="table table-sm mb-0 d-none" id="assign-table">
        <thead><tr><th>Tenant</th><th>Agent</th><th>Role</th><th>Version</th><th>Assigned</th></tr></thead>
        <tbody id="assign-body"></tbody>
      </table>
      <div id="assign-empty" class="card-body text-muted d-none">No active assignments.</div>
    </div>
  </div>
</div>`;

  const script = `<script>
(function(){
  var TID = ${JSON.stringify(templateId)};
  function fmt(iso) { return iso ? new Date(iso).toLocaleString() : '—'; }
  function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  // Fetch the template to list assignments via the template detail endpoint.
  // The admin API does not have a dedicated list-assignments endpoint; we use
  // the template detail and show the binding information from the assign call.
  function loadAssignments() {
    // There is no dedicated GET-assignments endpoint in the current API surface;
    // we show a placeholder and rely on the assign-response feedback.
    document.getElementById('assign-loading').classList.add('d-none');
    document.getElementById('assign-empty').classList.remove('d-none');
  }

  document.getElementById('btn-assign').onclick = function(){
    var tenant = document.getElementById('assign-tenant').value.trim();
    var agent = document.getElementById('assign-agent').value.trim();
    var role = document.getElementById('assign-role').value.trim();
    var versionRaw = document.getElementById('assign-version').value.trim();
    var errEl = document.getElementById('assign-error');
    var okEl = document.getElementById('assign-success');
    errEl.classList.add('d-none');
    okEl.classList.add('d-none');
    if (!tenant || !agent || !role) {
      errEl.textContent = 'Tenant, agent, and role are required.';
      errEl.classList.remove('d-none');
      return;
    }
    var binding = { tenantId: tenant, agentId: agent, role: role };
    if (versionRaw) binding.version = parseInt(versionRaw, 10);
    fetch('/api/v1/admin/templates/' + encodeURIComponent(TID) + '/assign', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, window.authHeaders()),
      body: JSON.stringify({ bindings: [binding] }),
    }).then(function(r){ return r.json().then(function(d){ return { ok: r.ok, data: d }; }); })
    .then(function(res){
      if (!res.ok) {
        errEl.textContent = (res.data.error && res.data.error.message) ? res.data.error.message : JSON.stringify(res.data);
        errEl.classList.remove('d-none');
        return;
      }
      var created = (res.data.created || []);
      var skipped = (res.data.skipped || []);
      if (created.length > 0) {
        okEl.textContent = 'Assigned! Assignment ID: ' + created[0].assignmentId;
        okEl.classList.remove('d-none');
        var tbody = document.getElementById('assign-body');
        created.forEach(function(a){
          var tr = document.createElement('tr');
          tr.innerHTML = '<td>' + escHtml(a.tenantId) + '</td>'
            + '<td>' + escHtml(a.agentId) + '</td>'
            + '<td>' + escHtml(a.role) + '</td>'
            + '<td><span class="badge bg-secondary badge-version">v' + a.version + '</span></td>'
            + '<td class="text-muted small">just now</td>';
          tbody.insertBefore(tr, tbody.firstChild);
          document.getElementById('assign-table').classList.remove('d-none');
          document.getElementById('assign-empty').classList.add('d-none');
        });
      } else if (skipped.length > 0) {
        okEl.textContent = 'Already assigned (skipped).';
        okEl.classList.remove('d-none');
      }
    }).catch(function(e){ errEl.textContent = 'Request failed: ' + e; errEl.classList.remove('d-none'); });
  };

  loadAssignments();
})();
</script>`;

  return pageShell('Template Assignments', body, script);
}

// ── Router factory ─────────────────────────────────────────────────────────

export function createAdminUiRouter(opts: AdminUiRouterOptions): Router {
  const router = Router();

  // Pre-compute the X-Admin-Key checker once at router creation time.
  const checkXAdminKey = createXAdminKeyChecker(opts.adminApiKey);

  // Auth guard: applies to all routes in this router.
  const authGuard = (req: Request, res: Response, next: NextFunction): void => {
    resolveAuth(req, checkXAdminKey, opts.jwtVerifier)
      .then((result) => {
        if (!result) {
          // If it looks like a browser request, add a hint; otherwise plain 401.
          const wantHtml = (req.headers['accept'] || '').includes('text/html');
          if (wantHtml) {
            res.status(401).send(
              pageShell(
                'Unauthorised',
                '<div class="alert alert-warning">'
                + 'Admin authentication required. Supply an <code>Authorization: Bearer &lt;token&gt;</code> '
                + 'header or append <code>?token=&lt;token&gt;</code> to the URL.</div>',
              ),
            );
          } else {
            next(
              new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Admin authentication required', 401),
            );
          }
          return;
        }
        res.locals['adminUiAuth'] = result;
        next();
      })
      .catch(next);
  };

  router.use(authGuard);

  // GET /admin/ → redirect to /admin/templates
  router.get('/', (_req: Request, res: Response) => {
    res.redirect(302, '/admin/templates');
  });

  // GET /admin/templates — list
  router.get('/templates', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderListPage());
  });

  // GET /admin/templates/new — create form
  router.get('/templates/new', (_req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderCreatePage());
  });

  // GET /admin/templates/:id/assign — assignment page
  // Must be registered BEFORE /templates/:id to avoid `:id` capturing "new".
  router.get('/templates/:id/assign', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderAssignPage(req.params['id'] ?? ''));
  });

  // GET /admin/templates/:id — detail + version history
  router.get('/templates/:id', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderDetailPage(req.params['id'] ?? ''));
  });

  return router;
}
