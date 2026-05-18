/**
 * Server-rendered admin UI for manifest templates — Task 7 of Stage 4.
 *
 * Serves pages under `/admin/` from the issuer's Express process.
 * All pages (except /admin/login) require the same authentication as the
 * admin API (either an operator JWT or the `X-Admin-Key` shared secret).
 *
 * Pages:
 *   GET  /admin/                           → redirect to /admin/templates
 *   GET  /admin/login                      → login page (no auth required)
 *   POST /admin/auth/session               → exchange JWT for session cookie
 *   DELETE /admin/auth/session             → clear session cookie (logout)
 *   GET  /admin/templates                  → list templates
 *   GET  /admin/templates/new              → create-template form
 *   GET  /admin/templates/:id              → detail + version history
 *   GET  /admin/templates/:id/assign       → assignment form + active assignments
 *
 * Auth:
 *   The bearer token may be supplied in:
 *     1. `euno_admin_session` HttpOnly cookie — set via POST /admin/auth/session.
 *        This is the preferred browser path and avoids writing tokens to URLs.
 *     2. `Authorization: Bearer <token>` header — programmatic / curl access.
 *     3. `X-Admin-Key: <secret>` header — shared-secret fallback.
 *
 *   The former `?token=` query-parameter path has been removed (DI-2) to
 *   prevent tokens from appearing in proxy access logs and browser history.
 *
 * Session cookie exchange flow (replaces ?token= — DI-2 fix):
 *   1. Caller POSTs { token: "<jwt>" } to POST /admin/auth/session.
 *   2. Server validates the JWT and sets
 *      Set-Cookie: euno_admin_session=<jwt>; HttpOnly; Secure; SameSite=Strict;
 *                  Path=/admin; Max-Age=3600
 *   3. Browser navigates to /admin/templates; cookie is sent automatically.
 *
 * All data calls go through the existing `/api/v1/admin/templates` API — there
 * are no UI-specific backend endpoints.  The server renders the page shell and
 * the client JavaScript fetches data from the admin API using the session token
 * embedded server-side in the page (never written to the URL).
 */

import * as crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import express, { Router, Request, Response, NextFunction } from 'express';
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
  /**
   * Max-Age for the `euno_admin_session` cookie in seconds. Defaults to 3600.
   */
  sessionMaxAgeSeconds?: number;
  /**
   * When false, the session cookie is issued without the `Secure` attribute
   * (useful for HTTP-only test environments). Defaults to true.
   */
  secureCookies?: boolean;
}

// ── Auth helper ────────────────────────────────────────────────────────────

interface AuthResult {
  operatorId: string;
  tenantId: string;
  isPlatformAdmin: boolean;
  /** The raw bearer token (JWT) that was verified, if one was used. */
  rawToken?: string;
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

/**
 * Parse the `Cookie` request header into a name→value map.
 * Handles URL-encoded values and ignores malformed pairs.
 */
function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) {
      try {
        out[name] = decodeURIComponent(value);
      } catch {
        out[name] = value;
      }
    }
  }
  return out;
}

/** Cookie name used for the server-side session. */
export const SESSION_COOKIE_NAME = 'euno_admin_session';

async function resolveAuth(
  req: Request,
  checkXAdminKey: ((provided: string) => boolean) | null,
  jwtVerifier?: IssuerAdminJwtVerifier,
): Promise<AuthResult | null> {
  // 1. Try session cookie (HttpOnly; set via POST /admin/auth/session).
  const cookies = parseCookies(req.headers['cookie']);
  const cookieToken = cookies[SESSION_COOKIE_NAME];
  if (cookieToken && jwtVerifier) {
    try {
      const principal = await jwtVerifier.verify(cookieToken);
      return {
        operatorId: principal.operatorId,
        tenantId: principal.tenantId,
        isPlatformAdmin: principal.isPlatformAdmin,
        rawToken: cookieToken,
      };
    } catch {
      // Cookie token invalid/expired — fall through to other methods.
    }
  }

  // 2. Try Bearer JWT from Authorization header.
  const authHeader = req.headers['authorization'];
  const headerToken =
    typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')
      ? authHeader.slice('bearer '.length).trim()
      : undefined;

  if (headerToken && jwtVerifier) {
    try {
      const principal = await jwtVerifier.verify(headerToken);
      return {
        operatorId: principal.operatorId,
        tenantId: principal.tenantId,
        isPlatformAdmin: principal.isPlatformAdmin,
        rawToken: headerToken,
      };
    } catch {
      // Fall through to X-Admin-Key path.
    }
  }

  // 3. Try X-Admin-Key shared secret (active only when adminApiKey was configured).
  if (checkXAdminKey) {
    const provided = req.headers['x-admin-key'];
    if (typeof provided === 'string' && checkXAdminKey(provided)) {
      return { operatorId: 'x-admin-key', tenantId: '', isPlatformAdmin: true };
    }
  }

  return null;
}

// ── HTML helpers ───────────────────────────────────────────────────────────

/**
 * Safely embed an arbitrary value as a JSON literal inside a `<script>` block.
 *
 * `JSON.stringify` alone is insufficient: a string like `</script>` in the
 * serialised output would break out of the script context.  We replace the
 * three characters that can cause premature script termination or HTML
 * injection with their Unicode escape sequences — these are valid inside
 * JSON string values and are transparently decoded by the JS engine.
 *
 * CI-4 fix: all dynamic values embedded in script contexts MUST go through
 * this helper rather than a bare `JSON.stringify`.
 */
function safeJsonEmbed(val: unknown): string {
  return JSON.stringify(val)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/\//g, '\\u002f')
    .replace(/&/g, '\\u0026');
}

/**
 * Render the full HTML page shell.
 *
 * @param title        Page `<title>` text (HTML-escaped automatically).
 * @param body         Inner HTML for the main content area (caller's responsibility to escape).
 * @param scriptExtra  Additional `<script>` blocks appended before `</body>`.
 * @param sessionToken The operator's raw JWT, embedded server-side so the
 *                     client-side JS can include it in API calls without
 *                     ever writing it to the URL or localStorage.
 */
function pageShell(title: string, body: string, scriptExtra = '', sessionToken?: string): string {
  // Embed the session token server-side.  We use safeJsonEmbed so that a
  // malformed token string cannot break out of the script block (CI-4).
  const tokenInit = sessionToken
    ? `window.__eunoAdminToken = ${safeJsonEmbed(sessionToken)};`
    : `window.__eunoAdminToken = '';`;
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
  <a class="nav-link text-muted small ms-auto" href="#" id="btn-logout">Log out</a>
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
        Not authenticated. <a href="/admin/login">Sign in</a>.
      </div>
      ${body}
    </main>
  </div>
</div>
<script>
// ── Token management ──────────────────────────────────────────────────────
(function () {
  // The session token is embedded server-side by the template renderer.
  // It is never written to the URL or localStorage (DI-2 fix).
  ${tokenInit}
  if (!window.__eunoAdminToken) {
    document.getElementById('auth-error').classList.remove('d-none');
  }
  // Show tenant from JWT sub
  if (window.__eunoAdminToken) {
    try {
      var parts = window.__eunoAdminToken.split('.');
      var p = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
      if (p.tenantId || p.tid) {
        document.getElementById('nav-tenant').textContent = 'tenant: ' + (p.tenantId || p.tid);
      }
    } catch (_) {}
  }
  window.authHeaders = function() {
    return window.__eunoAdminToken ? { 'Authorization': 'Bearer ' + window.__eunoAdminToken } : {};
  };
  document.getElementById('btn-logout').addEventListener('click', function(ev){
    ev.preventDefault();
    fetch('/admin/auth/session', { method: 'DELETE', credentials: 'same-origin' })
      .finally(function(){ window.location.href = '/admin/login'; });
  });
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

function renderListPage(sessionToken?: string): string {
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

  return pageShell('Templates', body, script, sessionToken);
}

// ── Page: create template ──────────────────────────────────────────────────

function renderCreatePage(sessionToken?: string): string {
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

  return pageShell('New Template', body, script, sessionToken);
}

// ── Page: template detail + version history ────────────────────────────────

function renderDetailPage(templateId: string, sessionToken?: string): string {
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
  var TID = ${safeJsonEmbed(templateId)};
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

  return pageShell('Template Detail', body, script, sessionToken);
}

// ── Page: assignments ──────────────────────────────────────────────────────

function renderAssignPage(templateId: string, sessionToken?: string): string {
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
  var TID = ${safeJsonEmbed(templateId)};
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

  return pageShell('Template Assignments', body, script, sessionToken);
}

// ── Router factory ─────────────────────────────────────────────────────────

export function createAdminUiRouter(opts: AdminUiRouterOptions): Router {
  const router = Router();
  const sessionMaxAge = opts.sessionMaxAgeSeconds ?? 3600;
  const secureCookies = opts.secureCookies !== false;

  // Pre-compute the X-Admin-Key checker once at router creation time.
  const checkXAdminKey = createXAdminKeyChecker(opts.adminApiKey);

  // ── Session cookie helpers ─────────────────────────────────────────────

  function setSessionCookie(res: Response, token: string): void {
    const cookieParts = [
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
      `Max-Age=${sessionMaxAge}`,
      'Path=/admin',
      'HttpOnly',
      'SameSite=Strict',
    ];
    if (secureCookies) cookieParts.push('Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
  }

  function clearSessionCookie(res: Response): void {
    const cookieParts = [
      `${SESSION_COOKIE_NAME}=`,
      'Max-Age=0',
      'Path=/admin',
      'HttpOnly',
      'SameSite=Strict',
    ];
    if (secureCookies) cookieParts.push('Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
  }

  // ── Pre-auth routes (no auth guard) ────────────────────────────────────

  // Rate limiter for the session exchange endpoint — 10 attempts per minute
  // per IP to prevent brute-force JWT validation attacks.
  const sessionExchangeRateLimit = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: { message: 'Too many session exchange attempts — please wait before retrying.' } },
  });

  // GET /admin/login — login page (no auth required)
  router.get('/login', (_req: Request, res: Response) => {
    const body = `
<div class="row justify-content-center mt-5">
  <div class="col-md-5">
    <div class="card shadow-sm">
      <div class="card-header fw-semibold">Sign in to Euno Admin</div>
      <div class="card-body">
        <p class="text-muted small mb-3">
          Paste your operator JWT below. The token will be sent to the server
          once and exchanged for a secure session cookie — it will never appear
          in a URL.
        </p>
        <div class="mb-3">
          <label for="login-token" class="form-label fw-semibold">Operator JWT</label>
          <textarea class="form-control font-monospace" id="login-token" rows="5"
            placeholder="eyJ..." spellcheck="false" autocomplete="off"></textarea>
        </div>
        <div id="login-error" class="alert alert-danger d-none"></div>
        <button class="btn btn-primary" id="btn-login">Sign in</button>
      </div>
    </div>
  </div>
</div>`;
    const script = `<script>
document.getElementById('btn-login').addEventListener('click', function(){
  var token = document.getElementById('login-token').value.trim();
  var errEl = document.getElementById('login-error');
  errEl.classList.add('d-none');
  if (!token) { errEl.textContent = 'Token is required.'; errEl.classList.remove('d-none'); return; }
  fetch('/admin/auth/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token }),
    credentials: 'same-origin',
  }).then(function(r){ return r.json().then(function(d){ return { ok: r.ok, data: d }; }); })
  .then(function(res){
    if (!res.ok) {
      errEl.textContent = (res.data.error && res.data.error.message) ? res.data.error.message : 'Authentication failed.';
      errEl.classList.remove('d-none');
    } else {
      window.location.href = '/admin/templates';
    }
  }).catch(function(e){ errEl.textContent = 'Request failed: ' + e; errEl.classList.remove('d-none'); });
});
</script>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(pageShell('Sign in', body, script));
  });

  // POST /admin/auth/session — exchange a JWT for a session cookie (DI-2 fix)
  //
  // Accepts JSON body { token: "<jwt>" } or Authorization: Bearer <jwt>.
  // Does NOT go through authGuard — this IS the auth establishment endpoint.
  //
  // Security notes:
  //  - Accepts only JSON bodies (Content-Type application/json) which prevents
  //    cross-origin form submissions from triggering a session.
  //  - SameSite=Strict on the resulting cookie prevents CSRF on all subsequent requests.
  //  - The JWT is validated before the cookie is issued.
  router.post('/auth/session', sessionExchangeRateLimit, express.json({ limit: '32kb' }), (req: Request, res: Response, next: NextFunction): void => {
    const rawToken: string | undefined =
      (typeof req.body?.token === 'string' && req.body.token ? req.body.token : undefined) ??
      (() => {
        const auth = req.headers['authorization'];
        return typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')
          ? auth.slice('bearer '.length).trim()
          : undefined;
      })();

    if (!rawToken) {
      res.status(400).json({ error: { message: 'token is required (body.token or Authorization: Bearer)' } });
      return;
    }

    if (!opts.jwtVerifier) {
      // Without a JWT verifier the session cookie path is unavailable; fall
      // back to informing the caller to use X-Admin-Key directly.
      res.status(501).json({ error: { message: 'JWT session exchange not configured on this issuer' } });
      return;
    }

    opts.jwtVerifier
      .verify(rawToken)
      .then(() => {
        setSessionCookie(res, rawToken);
        res.status(200).json({ ok: true });
      })
      .catch((err: unknown) => {
        opts.logger.warn('Admin UI session exchange failed', { err: String(err) });
        next(new CapabilityError(ErrorCode.AUTHENTICATION_FAILED, 'Invalid or expired token', 401));
      });
  });

  // DELETE /admin/auth/session — clear the session cookie (logout)
  router.delete('/auth/session', (_req: Request, res: Response) => {
    clearSessionCookie(res);
    res.status(200).json({ ok: true });
  });

  // ── Auth guard: applies to all remaining routes ─────────────────────────

  const authGuard = (req: Request, res: Response, next: NextFunction): void => {
    resolveAuth(req, checkXAdminKey, opts.jwtVerifier)
      .then((result) => {
        if (!result) {
          // Clear a stale/invalid session cookie so the browser does not
          // keep replaying it on every request.
          clearSessionCookie(res);
          // If it looks like a browser request, render a friendly 401 page;
          // otherwise emit a plain JSON error.
          const wantHtml = (req.headers['accept'] || '').includes('text/html');
          if (wantHtml) {
            res.status(401).send(
              pageShell(
                'Unauthorised',
                '<div class="alert alert-warning">'
                + 'Admin authentication required. '
                + '<a href="/admin/login">Sign in</a> or supply an '
                + '<code>Authorization: Bearer &lt;token&gt;</code> header.</div>',
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

  // ── Authenticated routes ────────────────────────────────────────────────

  // GET /admin/ → redirect to /admin/templates
  router.get('/', (_req: Request, res: Response) => {
    res.redirect(302, '/admin/templates');
  });

  // GET /admin/templates — list
  router.get('/templates', (_req: Request, res: Response) => {
    const auth = res.locals['adminUiAuth'] as AuthResult | undefined;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderListPage(auth?.rawToken));
  });

  // GET /admin/templates/new — create form
  router.get('/templates/new', (_req: Request, res: Response) => {
    const auth = res.locals['adminUiAuth'] as AuthResult | undefined;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderCreatePage(auth?.rawToken));
  });

  // GET /admin/templates/:id/assign — assignment page
  // Must be registered BEFORE /templates/:id to avoid `:id` capturing "new".
  router.get('/templates/:id/assign', (req: Request, res: Response) => {
    const auth = res.locals['adminUiAuth'] as AuthResult | undefined;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderAssignPage(req.params['id'] ?? '', auth?.rawToken));
  });

  // GET /admin/templates/:id — detail + version history
  router.get('/templates/:id', (req: Request, res: Response) => {
    const auth = res.locals['adminUiAuth'] as AuthResult | undefined;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderDetailPage(req.params['id'] ?? '', auth?.rawToken));
  });

  return router;
}
