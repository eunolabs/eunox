# eunox design

## Problem

A growing share of web and API traffic comes from AI agents and crawlers. Sites can't easily tell legitimate agents (acting for real users) from scrapers or attackers. Blocking all of them loses customers; allowing all of them is risky. Traditional bot protection was built to block, not to manage legitimate agents.

## Proposed minimal open-source component

Agent identity at the gateway, in both directions, from one core.

1. **Verify (built, v0)** — reuse existing Web Bot Auth libraries; normalize each request into a verified identity: operator, agent, and (if asserted) the user it acts on behalf of. Runs out of band on gateway access logs: no plugin, nothing in the request path.
2. **Sign (planned)** — the other direction, for organisations that run agents of their own: become a Web Bot Auth operator with `eunox sign`. Keys, a key directory, rotation, one key id per agent, and signing on the agent's egress path without the agent process holding the key. See "Operator side".
3. **Check (planned)** — a public signature checker: point an agent at it and see exactly what a verifier sees for that request.

Designed, not planned (see "Inline design"):

- **Inline classification and policy** — an Envoy-compatible ext\_authz service; declarative per-operator and per-agent rules for paths, methods, quotas and treatment of unsigned agents; an optional HTTP 402 hook.
- **Local behaviour scoring** — per-agent history on the site (error rates, scraping patterns, write bursts) that tightens limits on misbehaviour.
- **A shared cross-site reputation feed.**

## Architecture

This section describes the inline design (see "Inline design"), which is designed but not planned. What exists today is the observe path: the same verification logic run out of band on access logs (v0). The operator side's components are under "Operator side".

Fast, dumb, local data path; smart, asynchronous control path.

1. **Decision service (data path)** — Envoy-compatible ext\_authz server that Envoy and agentgateway call natively (nginx via auth\_request, Kong via a thin Lua plugin); in-process module only if the hop hurts. Parses signature headers, verifies against operator public keys fetched from key directories and cached locally. Output: verified identity (operator, agent, on-behalf-of user) or "unsigned". In observe mode (v0) the same logic runs out of band on access logs.
2. **Local policy engine** — identity + path + method + request features evaluated in-process (Cedar, OPA, or a small custom rule language). Decision: allow / deny / rate-limit / challenge / 402 payment. In-memory, microseconds, no network hop.
3. **Shared state** — Redis-class store for sliding-window counters and per-agent limits shared across gateway instances.
4. **Scoring job (async)** — consumes request logs out of band, detects bad patterns (error spikes, scraping, write bursts), writes tightened limits back to shared state.
5. **Control plane** — rule authoring, dashboard of which agents hit the site and how they behaved, config push to gateways. Future cross-site reputation feed plugs in here as another input.

## Status

| Part | What | Status |
| --- | --- | --- |
| v0 | Observe-only, from gateway access logs: verification, IP-range and FCrDNS checks, classification, counters, report page, metrics | Built; see "v0 status" |
| Signature checker | A public endpoint that shows what a verifier sees for one live request | Planned |
| `eunox sign` | Become an operator: keys, rotation, per-agent key ids, a self-signing directory server, a sidecar signer and a Playwright hook; the signer half of the same core | Planned |
| Inline design | The ext\_authz service, policy and in-process modules below | Designed, not planned |

Keep `core` I/O-free: the signer, sidecar and checker embed it, and it keeps the inline design possible.

### Inline design

Kept so the design stays coherent; not being built.

| Version | Deployment | Adds |
| --- | --- | --- |
| v1a | Envoy-compatible ext\_authz service | Classification passed to the upstream app as request headers; no enforcement |
| v1b | Same service | Path and method policy, per-agent quotas with state shared across instances, a serve-from-cache or throttle decision |
| Later | Same service | HTTP 402 and per-agent behaviour history |
| v2 | In-process modules | Nothing new; same core, no network hop |
| Egress policy | On the operator side | Site allowlists, per-agent 402 budgets, per-agent audit logs |

## Gateway integration

One Rust core. Today every gateway integrates through the observe path (access logs to a collector, v0). The inline and in-process columns below are the inline design (see Status), kept so the integration design is on record. The verifier needs only method, authority, original path, client IP, user agent and the Signature, Signature-Input and Signature-Agent headers. No body, so header-only hooks work everywhere.

| Gateway | Observe (v0, built) | Inline decision (v1, not planned) | In-process (v2, not planned) |
| --- | --- | --- | --- |
| Envoy (also Envoy Gateway, Istio, kgateway, Contour) | gRPC or OpenTelemetry access log | ext\_authz gRPC with failure\_mode\_allow | Rust dynamic module (ABI tied to Envoy X.Y and X.Y+1; a panic returns 500) |
| Kong | Bundled http-log plugin, no custom code | Thin Lua plugin calling the decision service over HTTP | LuaJIT FFI into the Rust core |
| nginx | log\_format plus syslog | auth\_request plus auth\_request\_set (fails closed unless worked around) | ngx-rust module (tied to one nginx version) |
| agentgateway | Access logs or OpenTelemetry (confirm it can log arbitrary headers) | extAuthz: Envoy-compatible gRPC, or HTTP | Upstream contribution in Rust |

### Integration gotchas

- **Client IP:** behind a CDN or load balancer, trusted-proxy settings (Envoy xff\_num\_trusted\_hops, nginx realip, Kong trusted\_ips) must be right, or IP-range checks mark real crawlers as spoofed.
- **Rewrites:** verify against the path the client sent. In nginx, log or forward $request\_uri, not $uri. Kong's http-log keeps the client's path in `request.uri` and the rewritten one in `upstream_uri` (checked with `strip_path`); an inline Kong plugin, if one is built, has to run before plugins that rewrite.
- **Fail-open:** Envoy has failure\_mode\_allow; nginx auth\_request fails closed by default; Envoy dynamic modules fail closed on panic.
- **No blocking I/O on workers:** when the core runs in-process, key-directory fetches happen in the background, never on the request path.
- **Reverse DNS suffixes must be operator-only:** `googleusercontent.com` (including `gae.googleusercontent.com`) is customer-controlled Google Cloud and App Engine address space, so it proves nothing about Google's own agents. Accept only suffixes the operator alone controls (`googlebot.com`, `crawl.commoncrawl.org`).
- **Key directories are rarer than signing claims suggest:** on 2026-11-08 only OpenAI (`chatgpt.com`) and Google (`agent.bot.goog`) served one at the well-known path. Google's `kid`s are short ids, not JWK thumbprints, so index keys by both.
- **Skip Kong Wasm:** Kong's ngx\_wasm\_module has had no pushes since May 2025.

## v0 build design

Goal: one Docker image that receives gateway access logs, verifies and classifies agent traffic out of band, and shows a useful report on day one. Nothing sits in the request path: zero added latency, no way to break the site's traffic, no data leaving their environment. Integrating is a config change (paste a snippet, reload), not a plugin install.

### Scope

- In: log receivers for Envoy, nginx and Kong, out-of-band Web Bot Auth verification, published-IP-range and reverse-DNS checks, claimed-vs-verified classification, in-memory counters, local report page, OpenTelemetry metrics.
- Out: anything inline (ext\_authz, headers to downstream apps), enforcement, policy language, shared state, control plane, scoring, app middleware, in-process modules.

### Classification (every request gets one)

First match wins.

- **verified** — valid Web Bot Auth signature from a known key directory, inside its validity window at the log timestamp. Overrides the user agent and IP.
- **ip-verified** — claims a known agent, and the client IP is in that agent's published ranges or passes forward-confirmed reverse DNS under one of its documented suffixes. Ranges are per agent: an IP in GPTBot's ranges doesn't verify a ChatGPT-User claim.
- **spoofed** — claims a known agent, and every check that agent supports ran and failed.
- **unknown-bot** — a bot that can't be attributed or checked: a generic bot or automation user agent, a signature from an unknown signer or under an unsupported scheme, or a known-agent claim with no way to check it (the agent publishes no ranges or reverse-DNS names, its range data isn't loaded yet, or the DNS lookup got no answer).
- **unclassified** — everything else (presumed human).

A request claims an agent through its user agent, an unsigned `Signature-Agent`, or a failed signature whose key belongs to a known operator. A failed signature on its own decides nothing; the IP checks do. So a genuine signature replayed from the operator's own network is ip-verified, and one replayed from elsewhere is spoofed. Missing data never produces spoofed.

Only `tag="web-bot-auth"` signatures are verified. Signatures under other tags, such as Visa Trusted Agent Protocol's `agent-browser-auth` and `agent-payer-auth`, are recorded with their tag and reported as an unsupported scheme.

### Inputs (what each gateway logs)

- Timestamp, method, scheme, the Host header as the client sent it (port included: nginx `$http_host`, falling back to `$host`), original path (nginx `$request_uri`), client IP after trusted-proxy resolution, user agent.
- `Signature`, `Signature-Input` and `Signature-Agent` headers, logged verbatim.
- Volume control: small sites log everything; larger ones filter at the gateway to requests carrying signature headers or bot-like user agents.
- Verification uses the log timestamp, not the time the log arrives, so `created`/`expires` windows still check correctly.

The nginx snippet (field names are the contract; `ts` may also be `$msec`, and a `status` field is optional):

```nginx
log_format eunox escape=json
  '{"ts":"$time_iso8601",'
  '"method":"$request_method",'
  '"scheme":"$scheme",'
  '"host":"$host",'
  '"authority":"$http_host",'
  '"path":"$request_uri",'
  '"ip":"$remote_addr",'
  '"ua":"$http_user_agent",'
  '"sig":"$http_signature",'
  '"sig_input":"$http_signature_input",'
  '"sig_agent":"$http_signature_agent"}';

access_log syslog:server=127.0.0.1:5140 eunox;
```

nginx sends syslog over UDP only, so datagrams can be lost under load. Lines that can't be parsed are counted with the reason. Log shippers can instead send the same JSON lines over TCP, and a saved access log can be replayed.

The Envoy snippet uses Envoy's built-in OpenTelemetry access logger, which sends each request to eunox as an OTLP log record over gRPC (port 4317), one attribute per field. Attribute names are the nginx field names; the request start time is the record's time. Tested with Envoy 1.32.

```yaml
# In the HTTP connection manager:
access_log:
- name: envoy.access_loggers.open_telemetry
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.access_loggers.open_telemetry.v3.OpenTelemetryAccessLogConfig
    common_config:
      log_name: eunox
      transport_api_version: V3
      grpc_service:
        envoy_grpc: { cluster_name: eunox }
    attributes:
      values:
      - { key: method, value: { string_value: "%REQ(:METHOD)%" } }
      - { key: scheme, value: { string_value: "%REQ(:SCHEME)%" } }
      - { key: authority, value: { string_value: "%REQ(:AUTHORITY)%" } }
      - { key: path, value: { string_value: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%" } }
      - { key: ip, value: { string_value: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%" } }
      - { key: status, value: { string_value: "%RESPONSE_CODE%" } }
      - { key: ua, value: { string_value: "%REQ(USER-AGENT)%" } }
      - { key: sig, value: { string_value: "%REQ(SIGNATURE)%" } }
      - { key: sig_input, value: { string_value: "%REQ(SIGNATURE-INPUT)%" } }
      - { key: sig_agent, value: { string_value: "%REQ(SIGNATURE-AGENT)%" } }

# Under static_resources.clusters:
- name: eunox
  type: STRICT_DNS
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config: { http2_protocol_options: {} }
  load_assignment:
    cluster_name: eunox
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address: { address: eunox.internal, port_value: 4317 }
```

`%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%` is the client after Envoy's trusted-proxy handling (`xff_num_trusted_hops`, `use_remote_address`), and `X-ENVOY-ORIGINAL-PATH` is the path before route rewrites. Envoy writes `-` for a missing header, which eunox reads as absent. The same receiver accepts OTLP logs from an OpenTelemetry Collector, either with these attributes or with an nginx JSON line as the log body.

For Kong, enable its bundled `http-log` plugin (globally or per service), pointing at the eunox host's port 8041. Nothing to install: eunox reads Kong's standard log serializer output. `request.uri` is the original path and query, and `client_ip` is the client after Kong's `trusted_ips` and `real_ip_header` handling. Batched bodies (a JSON array) and single entries both work.

```yaml
plugins:
- name: http-log
  config:
    http_endpoint: http://eunox.internal:8041/
    method: POST
    content_type: application/json
    queue:
      max_batch_size: 100
      max_coalescing_delay: 1
```

### Components (Rust workspace)

1. `core` crate — pure library, no I/O: parse RFC 9421 signature headers, verify at a supplied timestamp (reuse Cloudflare's web-bot-auth crate where possible), match IP ranges, classify. The same crate backs the signer and the checker, and would back the ext\_authz service and in-process modules if they are built.
2. `directory` module — fetch and cache operator key directories and published IP range files on a timer (hourly); seed list of known operators (OpenAI, Anthropic, Perplexity, Google, Common Crawl). Sources that fail to load are retried on their own, starting after 30 seconds and doubling up to the refresh interval, so a source that comes up after eunox loads within seconds without refetching the healthy ones.
3. `ingest` binary — receivers that normalize every source into one request record: syslog (UDP/TCP, JSON lines) for nginx, gRPC Access Log Service or OTLP logs for Envoy, an HTTP endpoint for Kong's http-log.
4. `stats` module — in-memory counters per row (an agent, operator or bot marker, and its class) behind a mutex; at the measured ingest rate a lock-free structure buys nothing. Rolling 24h window that ends at the newest log timestamp, so a replayed log reports its own day. Per row: requests per minute, top paths and client networks per hour, last seen. Rows are capped, because labels come partly from user agents. Also counts unknown signers by `Signature-Agent` origin, so operators that sign without a known key directory are visible. Their directories are added to the source list by hand, never fetched from a request.
5. `report` — served by `eunox serve`: `/` (page: class totals, top agents with top paths and networks, unknown signers, source freshness, ingest health), `/report.txt` (the same as text, also printed by `eunox report`), `/metrics` (Prometheus) and `/healthz`. The same series can be pushed over OTLP gRPC to an OpenTelemetry Collector or any OTLP backend (`EUNOX_OTLP_METRICS_ENDPOINT`): counters as cumulative monotonic sums from process start (`eunox.requests` by class and catalog agent, `eunox.ingest.*`, `eunox.rdns.*`), and gauges for the window counts by class and source health (`eunox.window.requests`, `eunox.source.up`). A failed export is logged and retried on the next tick.

### Packaging

- One container image for linux/amd64 and linux/arm64, with `eunox` and the demo traffic generator `eunox-demo`; config via env vars only. The `image` workflow publishes it to `ghcr.io/eunolabs/eunox`: `main` and `sha-<commit>` on every push to main, and `X.Y.Z`, `X.Y` and `latest` on a `vX.Y.Z` tag. Its build stage cross-compiles on the runner's own platform, so arm64 needs no emulation. Pushed images are signed by digest with cosign (keyless, GitHub OIDC identity) and carry a build provenance attestation; the verify commands are in the workflow header.
- One binary, `eunox`:
  - `eunox serve` receives logs and serves the report.
  - `eunox replay [FILE]` classifies a saved log and prints the report.
  - `eunox report` prints a running server's report.
- Environment (`eunox --help` lists them with defaults): `EUNOX_SYSLOG_UDP` (0.0.0.0:5140), `EUNOX_LINES_TCP` (off), `EUNOX_OTLP_GRPC` (0.0.0.0:4317), `EUNOX_KONG_HTTP` (0.0.0.0:8041), `EUNOX_HTTP` (0.0.0.0:8040), `EUNOX_RDNS` (on), `EUNOX_REFRESH_SECS` (3600), `EUNOX_SEED_SOURCES` (on), `EUNOX_OTLP_METRICS_ENDPOINT` (off) with `EUNOX_OTLP_METRICS_INTERVAL_SECS` (60), and `EUNOX_KEY_DIRECTORIES` / `EUNOX_RANGES` for extra sources as `id=url,...`.
- `docker compose up` demo: Envoy and nginx in front of a sample upstream, plus a traffic generator sending signed, spoofed and plain requests, so the report fills within seconds. It pulls the published image and builds from the checkout if the pull fails.
- Copy-paste snippets: Envoy `access_log` block, nginx `log_format` and `access_log syslog:` lines, Kong http-log plugin config.

### What's built

- `core`: signature verification at a supplied timestamp, tested against Cloudflare's test keys; IP-range and reverse-DNS checks and classification, with lookup results passed in (fetching ranges and DNS lookups live in `directory`).
- `ingest` with the nginx receivers (UDP syslog, TCP JSON lines, file replay), normalization and classification. About 180k lines/s on one thread.
- Counters, report page, `/metrics`, the `eunox` binary (`serve`, `replay`, `report`), extra key directories and range files from env, and [docs/testing.md](testing.md).
- Dockerfile, compose demo with a traffic generator that signs fresh requests (nginx and Envoy), README quickstart.
- Envoy receiver: OTLP logs over gRPC from Envoy's OpenTelemetry access logger, tested against Envoy 1.32.
- Kong receiver: the bundled `http-log` plugin, single entries and batches. Tested against Kong's documented log serializer format and a live Kong 3.9.4, including a `strip_path` route.
- Published image: built for linux/amd64 and linux/arm64 and pushed to GHCR from main and version tags; the compose demo pulls it.
- Alerting: Prometheus rules in `deploy/prometheus/eunox-alerts.yml` for a high spoofed share, a source that stays down, parse errors and no log lines, with promtool unit tests.
- UDP loss: nginx's `access_log syslog:` is UDP only, and a lost datagram leaves no trace. When any line arrived over UDP, the report says so under the totals, and `/metrics` exposes `eunox_ingest_udp_datagrams_total` to compare with the gateway's own request count.

### Done when

- Fresh machine to report page in under 60 seconds with the compose demo.
- A signed test request shows as verified; a forged GPTBot user agent shows as spoofed.
- Integrating an existing Envoy or nginx is a pasted snippet and a reload: no plugin, no binary added to the gateway, no added request latency.
- Ingest keeps up with at least 10k log lines per second on a laptop.

### v0 status

| Done when | Status |
| --- | --- |
| Fresh machine to report page in under 60 seconds with the compose demo | Not yet measured. The demo downloads about 120 MB compressed: eunox 38 MB, Envoy 60 MB, nginx 21 MB. With the images pulled from a local registry, the report shows `verified` and `spoofed` about 5 seconds after `docker compose up`. So under 60 seconds needs roughly 20 Mbit/s or more, once the published image can be pulled anonymously. Until then, compose builds the image: about 2 minutes on 4 cores, plus a 2 GB Rust image |
| A signed test request shows as verified; a forged GPTBot as spoofed | Yes, from live traffic: the compose demo's generator signs fresh requests through nginx and Envoy |
| Integrating nginx or Envoy is a pasted snippet and a reload | Yes for both: nginx `log_format` plus `access_log syslog:`, Envoy `access_log` block plus one cluster. Kong too: enable the bundled `http-log` plugin |
| Ingest at 10k lines/s or more | Yes: about 180k lines/s on one thread, in process |

Not done yet: the `ghcr.io/eunolabs/eunox` package is private, so anonymous pulls fail and compose falls back to building; the compose demo hasn't been timed on a fresh machine. The first push to main creates the package, and GHCR makes a new organization package private. Public can't be undone, so it goes with making the repository public.

How to test what exists: [testing.md](testing.md).

### Open decisions

- Name and repo under eunolabs vs a new org.
- License: Apache-2.0 for the core.
- Operator side: whether the major registries identify an agent by its directory URL or by key id (see "Operator side", item 4).


### Operator side (planned)

The verifier only works for agents whose operator publishes a key directory. Today very few do, and an organisation that runs its own agents (browser agents, crawlers, API clients) has no self-hosted way to become one: Cloudflare's libraries produce a signature, but keys, directory hosting, rotation and per-agent identity are left to the deployer. `eunox sign` is the same core used in the other direction.

**Public signature checker.** A URL an agent builder points their agent at. It returns exactly what a verifier sees for that one request: `Signature-Input` and `Signature` parsed, the `Signature-Agent` directory fetched, which key matched, and what failed and why (unknown tag, expired `created`, uncovered component, legacy `Signature-Agent` form, key id not in the directory, directory response not signed or served with the wrong media type). It's the v0 classifier applied to a single live request. Builds on the existing core, and debugs signing against any verifier, not just eunox.

**`eunox sign`.** The pieces:

1. `eunox sign init`: generate an Ed25519 operator key, write a JWKS, and emit a signed test request the checker accepts. Keys stored on disk or read from a secret manager; never printed.
2. Directory server: serves `/.well-known/http-message-signatures-directory` with the right media type and cache headers, or exports a static file for a CDN. The directory draft has the server sign its own response (RFC 9421 over the response, `tag="http-message-signatures-directory"`, keyed by the directory's own keys), and registries check it; the static export therefore has to be re-signed on every change and before `expires`, so the export is a command, not a one-off file. Confirm against the current draft before building.
3. Rotation in three steps, each one verifier cache lifetime apart: publish the new key alongside the old one; start signing with the new key; remove the old key. Publishing and switching at once breaks every verifier holding a cached directory, which is the failure the done-when rules out. The cache lifetime is the directory's own `Cache-Control` max-age, so the tool knows the wait.
4. One key id per agent under one operator: `acme.example` signs for `procurement-agent` and `support-bot` with different `kid`s, so a verifier that keys on `kid` (eunox does) can tell them apart and the operator can revoke one without touching the other. A registry that identifies an agent by its directory URL sees one agent; if that's how the major registries work, per-agent identity there needs one directory per agent (a subdomain or path each), and the directory server has to serve several. Not yet confirmed.
5. Signing on the egress path, with the key held outside the agent process:
   - a sidecar for API-style agents. It's a reverse proxy, not a forward proxy: the agent sends plain HTTP to `localhost` with the real destination in the path or a header, and the sidecar signs and originates the HTTPS request. A forward proxy would have to either sign inside a `CONNECT` tunnel, which it can't see into, or hold a local CA that every agent trusts; neither is worth it for a sidecar. The cost is that each agent's base URL changes;
   - a Playwright/Chromium hook for browser agents (route interception adds the headers before the request leaves). The hook needs the signature without the key, so it calls the sidecar for the headers;
   - a small Rust library for agents that want to sign in-process anyway. The library is the commodity; the service is the point. Python and Node bindings only if asked for.
6. A registration checklist for the public directories (Cloudflare's, and others as they appear), since publishing a directory is necessary and not sufficient to be treated as verified.

Not in scope: egress policy (site allowlists, per-agent budgets for HTTP 402 responses) and per-agent audit logs (see "Inline design").

**Components:** the signer half lives in `core` (`web-bot-auth` already signs; the demo traffic generator uses it today). `eunox sign` is a subcommand group on the existing binary; the directory server shares the HTTP stack with `eunox serve`. The checker is `eunox serve` with one extra endpoint, deployable on its own.

**Done when:** `eunox sign init` plus a one-line sidecar or Playwright config produces requests that the checker, the v0 verifier and at least one major third-party verifier all report as verified from the operator's own directory; the directory response itself passes the checker; and a key rotation carried out with the three-step sequence breaks nothing for a verifier that cached the old directory.

### Request records

- Every record carries a stable per-agent session key: operator plus key id for verified signatures. Otherwise IP plus user agent, labelled as a heuristic, because agents behind shared cloud egress collide.
- Every record carries the `tag` of each `Signature-Input` label (for example `web-bot-auth`, `agent-browser-auth` or `agent-payer-auth`), whether or not the signature verified.
- Keep the schema extensible so later work can tie request sequences to orders (`mandate_ref`, `order_ref`).
- Don't keep per-session path sequences in v0: it turns lock-free counters into an event store, works against the 10k lines/s target and holds per-client path history. The gateway's own access logs already have the sequence and can be replayed.

### Agent catalog

- `crates/core/data/agents.toml` was seeded from AgentSniff's Apache-2.0 catalog (`agent_clients.json` 2.6.0), with attribution in the file. We maintain our own copy and send corrections upstream.
- Read their data; don't link their crates (tokio stack, synchronous engine, their release cadence and id renames).
- User policy names eunox ids only, never theirs, so upstream renames can't break it.
