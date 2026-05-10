/* Shared JS for the Euno static site
   - terminal animation (#term)
   - install snippet copy buttons
   - smooth scroll to in-page anchors with sticky-header offset
*/

(function () {
  'use strict';

  // ── Terminal animation ────────────────────────────────────────────
  const TERM_LINES = [
    { cls: 't-info',   text: '  euno-mcp v0.2 · policy proxy for MCP' },
    { cls: 't-dim',    text: '' },
    { cls: 't-info',   text: '  upstream  npx @modelcontextprotocol/server-filesystem /data' },
    { cls: 't-info',   text: '  policy    ./euno.policy.yaml  (3 capabilities, 12 conditions)' },
    { cls: 't-ok',     text: '  ✓ proxy listening on stdio' },
    { cls: 't-dim',    text: '' },
    { cls: 't-purple', text: '  → tools/call  read_file  { path: "/data/report.csv" }' },
    { cls: 't-ok',     text: '  ✓ allowed  [ext .csv ∈ allowedExtensions]' },
    { cls: 't-dim',    text: '' },
    { cls: 't-purple', text: '  → tools/call  read_file  { path: "/data/keys.pem" }' },
    { cls: 't-err',    text: '  ✗ denied   extension .pem not in allowedExtensions' },
    { cls: 't-info',   text: '    ↳ upstream never contacted · audited to ~/.euno/audit.jsonl' },
    { cls: 't-dim',    text: '' },
    { cls: 't-purple', text: '  → tools/call  query  { sql: "DROP TABLE users" }' },
    { cls: 't-err',    text: '  ✗ denied   operation DROP not in allowedOperations' },
    { cls: 't-info',   text: '    ↳ upstream never contacted' },
    { cls: 't-dim',    text: '' },
    { cls: 't-purple', text: '  → tools/call  send_dm  { to: "x@evil.com" }' },
    { cls: 't-err',    text: '  ✗ denied   recipient domain not in allowlist' }
  ];

  function runTerminal() {
    const body = document.getElementById('term-body');
    if (!body) return;
    body.innerHTML = '';
    let delay = 250;
    TERM_LINES.forEach(function (l) {
      const row = document.createElement('div');
      row.className = 't-line ' + l.cls;
      row.style.animationDelay = delay + 'ms';
      row.textContent = l.text || '\u00a0';
      body.appendChild(row);
      delay += l.text ? 150 : 70;
    });
  }

  function initTerminal() {
    const termEl = document.getElementById('term');
    if (!termEl) return;
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { if (e.isIntersecting) runTerminal(); });
      }, { threshold: 0.2 });
      observer.observe(termEl);
    }
    runTerminal();
  }

  // ── Copy install command ──────────────────────────────────────────
  function announce(msg) {
    const a = document.getElementById('copy-announce');
    if (a) a.textContent = msg || '';
  }

  function copyText(text, btn) {
    function ok() {
      if (btn) btn.textContent = 'copied!';
      announce('Command copied to clipboard.');
      setTimeout(function () {
        if (btn) btn.textContent = 'copy';
        announce('');
      }, 2000);
    }
    function fail() {
      if (btn) btn.textContent = 'copy failed';
      announce('Copy failed. Please select and copy the command manually.');
      setTimeout(function () {
        if (btn) btn.textContent = 'copy';
        announce('');
      }, 2500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(ok, fail);
    } else {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.className = 'sr-only';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const success = document.execCommand('copy');
        document.body.removeChild(ta);
        if (success) ok(); else fail();
      } catch (_) { fail(); }
    }
  }

  function initCopyButtons() {
    document.querySelectorAll('.install-snippet').forEach(function (el) {
      el.addEventListener('click', function () {
        const cmdEl = el.querySelector('.cmd');
        const btn   = el.querySelector('.copy-btn');
        if (cmdEl) copyText(cmdEl.textContent, btn);
      });
    });
  }

  // ── Smooth scroll with sticky-header offset ───────────────────────
  function getTopHeaderOffset() {
    const h = document.querySelector('header.site-header');
    if (!h) return 0;
    const r = h.getBoundingClientRect();
    return r.top <= 0 ? r.height : 0;
  }

  function scrollToAnchor(el) {
    const headerOffset = getTopHeaderOffset();
    const top = Math.max(el.getBoundingClientRect().top + window.pageYOffset - headerOffset - 16, 0);
    window.scrollTo({ top: top, behavior: 'smooth' });
  }

  function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(function (a) {
      const href = a.getAttribute('href');
      if (!href || href === '#' || href.length < 2) return;
      a.addEventListener('click', function (e) {
        const id = href.slice(1);
        const el = document.getElementById(id);
        if (el) {
          e.preventDefault();
          scrollToAnchor(el);
          if (history.replaceState) history.replaceState(null, '', '#' + id);
        }
      });
    });
  }

  // ── Boot ──────────────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
  function boot() {
    initTerminal();
    initCopyButtons();
    initSmoothScroll();
  }
})();
