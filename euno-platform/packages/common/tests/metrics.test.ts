/**
 * Tests for the shared Prometheus / OpenMetrics helpers
 * (F-5, addresses I-16 in `docs/IMPROVEMENTS_AND_REFACTORING.md`).
 */

import express from 'express';
import request from 'supertest';

import {
  Counter,
  createHttpMetricsMiddleware,
  createMetricsHandler,
  createMetricsRegistry,
} from '../src/metrics';

describe('createMetricsRegistry', () => {
  it('attaches the service name as a default label', async () => {
    const registry = createMetricsRegistry({
      serviceName: 'unit-test-service',
      collectDefaults: false,
    });
    const counter = new Counter({
      name: 'unit_test_counter',
      help: 'a test counter',
      registers: [registry],
    });
    counter.inc();

    const text = await registry.metrics();
    expect(text).toContain('service="unit-test-service"');
    expect(text).toContain('unit_test_counter');
  });

  it('omits Node.js process metrics when collectDefaults=false', async () => {
    const registry = createMetricsRegistry({
      serviceName: 'no-defaults',
      collectDefaults: false,
    });
    const text = await registry.metrics();
    expect(text).not.toContain('process_cpu_seconds_total');
  });
});

describe('createHttpMetricsMiddleware + createMetricsHandler', () => {
  function buildApp() {
    const registry = createMetricsRegistry({
      serviceName: 'mw-test',
      collectDefaults: false,
    });
    const app = express();
    app.use(createHttpMetricsMiddleware({ registry }));
    app.get('/ping', (_req, res) => res.json({ ok: true }));
    app.get('/users/:id', (req, res) => res.json({ id: req.params.id }));
    app.get('/metrics', createMetricsHandler(registry) as express.RequestHandler);
    return app;
  }

  it('serves Prometheus exposition with the correct content-type', async () => {
    const app = buildApp();

    const res = await request(app).get('/metrics');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/plain/);
    expect(res.headers['content-type']).toContain('version=0.0.4');
    expect(res.text).toContain('# HELP euno_http_requests_total');
    expect(res.text).toContain('# HELP euno_http_request_duration_seconds');
  });

  it('records request count + duration labelled by method/route/status', async () => {
    const app = buildApp();

    await request(app).get('/ping');
    await request(app).get('/ping');
    const res = await request(app).get('/metrics');

    expect(res.text).toMatch(
      /euno_http_requests_total\{[^}]*method="GET"[^}]*route="\/ping"[^}]*status_code="200"[^}]*\}\s+2/,
    );
    expect(res.text).toMatch(
      /euno_http_request_duration_seconds_count\{[^}]*route="\/ping"[^}]*\}\s+2/,
    );
  });

  it('uses the matched route pattern (not raw URL) to bound cardinality', async () => {
    const app = buildApp();

    await request(app).get('/users/abc');
    await request(app).get('/users/xyz');
    const res = await request(app).get('/metrics');

    // Two requests should collapse onto a single labelled time-series.
    expect(res.text).toMatch(
      /euno_http_requests_total\{[^}]*route="\/users\/:id"[^}]*\}\s+2/,
    );
    // Raw user IDs must NOT appear as label values.
    expect(res.text).not.toContain('route="/users/abc"');
    expect(res.text).not.toContain('route="/users/xyz"');
  });

  it('skips the /metrics endpoint itself so scrapes do not pollute series', async () => {
    const app = buildApp();

    await request(app).get('/metrics');
    await request(app).get('/metrics');
    const res = await request(app).get('/metrics');

    expect(res.text).not.toMatch(
      /euno_http_requests_total\{[^}]*route="\/metrics"/,
    );
  });

  it('returns 405 for non-GET requests to /metrics when mounted with app.use', async () => {
    const registry = createMetricsRegistry({
      serviceName: 'use-mount',
      collectDefaults: false,
    });
    const app = express();
    app.use(createMetricsHandler(registry) as express.RequestHandler);

    const res = await request(app).post('/metrics').send({});
    expect(res.status).toBe(405);
  });
});
