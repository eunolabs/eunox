# eunox — agent identity at the gateway, both directions

## What this is
An open-source tool for Web Bot Auth agent identity, in both directions from one core. Inbound (built, v0): it tells a site which AI agents are hitting it and which of them are who they claim to be. Outbound (partly built): the operator side, `eunox sign`, so an organisation running its own agents can publish a key directory and sign their requests without the agent process holding the key, plus a public signature checker (planned) (design: "Operator side" in `docs/design.md`).

## Product principles
- Plain Web Bot Auth signature verification is a commodity (Cloudflare, AWS WAF, Akamai, HUMAN and Vercel already ship it). eunox adds classification across every identity source, and the operator side: custody, the key directory, rotation and per-agent identity for organisations running their own agents.
- Interoperate with agent-side governance tools through standard Web Bot Auth signing; don't couple to any of them.

## v0 scope
Observe-only via gateway access logs. Nothing in the request path: zero added latency, can't break the site's traffic, no data leaves the site's environment.

- In: log receivers (nginx syslog JSON lines, Envoy gRPC Access Log Service or OTLP logs, Kong http-log), out-of-band Web Bot Auth verification at the log timestamp, published-IP-range and forward-confirmed reverse-DNS checks, classification, in-memory counters, local report page, `/metrics` and OTLP export.
- Out: ext_authz, enforcement, headers to downstream apps, policy language, shared state, control plane, scoring, app middleware, in-process modules.

### Classification (every request gets exactly one)
- `verified`: valid Web Bot Auth signature from a known key directory.
- `ip-verified`: no signature, but the source IP is in the operator's published ranges (or passes forward-confirmed reverse DNS) and matches the claimed user agent.
- `spoofed`: claims a known agent (user agent or Signature-Agent) and fails every check that agent supports. Missing data never produces `spoofed`.
- `unknown-bot`: a bot that can't be attributed or checked: generic bot or automation user agent, unknown signer or unsupported signature scheme, or a known-agent claim with no way to check it (no published ranges or reverse DNS, data not loaded, DNS unanswered).
- `unclassified`: everything else (presumed human).

### Inputs the gateway must log
Timestamp, method, scheme, the Host header as sent (nginx `$http_host`, which keeps the port), original path (nginx `$request_uri`, not `$uri`), client IP after trusted-proxy resolution, user agent, and the `Signature`, `Signature-Input` and `Signature-Agent` headers verbatim.

## Architecture (Rust workspace)
- `core`: pure library, no I/O. Parses RFC 9421 signature headers, verifies at a supplied timestamp (reuse Cloudflare's web-bot-auth crate where possible), matches IP ranges, classifies. It must stay I/O-free because it will later back an ext_authz server, an Envoy dynamic module and LuaJIT FFI for Kong.
- `directory`: fetches and caches operator key directories and published IP-range files on a timer. Seed operators: OpenAI, Anthropic, Perplexity, Google, Common Crawl.
- `ingest`: receivers that normalize every log source into one request record.
- `stats`: in-memory counters per agent and class, rolling 24h window ending at the newest log timestamp.
- Operator side (partly built): the signer half of `core` (`core::sign`, built), a `sign` subcommand group (`init`, `request`, `serve` and `export` built; rotation, per-agent key ids, sidecar and Playwright hook planned) and a public signature checker endpoint (planned). Keys never live in the agent process.
- Packaging: `Dockerfile` builds one image with `eunox` and the demo traffic generator `eunox-demo`, for linux/amd64 and linux/arm64 (the build stage cross-compiles). `.github/workflows/image.yml` publishes it to `ghcr.io/eunolabs/eunox`: `main` from the main branch, versions from `vX.Y.Z` tags. `docker-compose.yml` is the demo; it pulls that image, or builds it if the pull fails, with gateway configs in `deploy/demo/`.
- `report`: served by the `eunox` binary (`serve`, `replay`, `report`): HTTP page with top agents, verified vs spoofed share, top paths per agent and last-seen times, plus `/report.txt`, `/metrics` and `/healthz`, and OTLP metrics push (`EUNOX_OTLP_METRICS_ENDPOINT`).

Designed, not planned (see "Inline design" in `docs/design.md`):
- v1a: an Envoy-compatible ext_authz gRPC server (tonic) that classifies and passes the result to the upstream as headers, with no enforcement. Envoy and agentgateway call it natively, nginx through auth_request (HTTP variant) and Kong through a thin Lua plugin.
- v1b: on the same server, path and method policy and per-agent quotas with state shared across instances. HTTP 402 and per-agent behaviour history come later, when a deployment needs them.
- v2: in-process modules, only if someone needs to avoid the extra hop.

Roadmap, ordering and schedule aren't kept in this repo. Don't start the planned parts (the rest of `eunox sign`, the checker) or the designed-only ones unless the owner asks for them. Full design: `docs/design.md`. How to test, including against real nginx: `docs/testing.md`. v0 status and remaining work: the "v0 status" section of `docs/design.md`.

## Gotchas
- Client IP: behind a CDN or load balancer, trusted-proxy settings must be right, or IP checks mark real crawlers as spoofed.
- Verify against the path the client sent, never a rewritten one.
- When running in-process later, never do blocking I/O on gateway worker threads; fetch key directories in the background.
- Don't build on Kong's Wasm support; it appears stalled.
- Request records carry a per-agent session key (operator plus key id when signed; IP plus user agent is a labelled heuristic) and the `Signature-Input` tag, and leave room for `mandate_ref` and `order_ref`. Don't store per-session path sequences in v0: the gateway's own logs can be replayed later.
- Keep business strategy out of this repo (code, docs, commit messages, PR descriptions): market and competitor analysis, positioning, target customers, outreach. This repo is going public.

## Done when (v0)
- Fresh machine to report page in under 60 seconds with `docker compose up` (Envoy and nginx in front of a sample upstream, plus a traffic generator sending signed, spoofed and plain requests).
- A signed test request shows as `verified`; a forged GPTBot user agent shows as `spoofed`.
- Integrating an existing Envoy or nginx is a pasted snippet and a reload: no plugin, no binary added to the gateway.
- Ingest handles at least 10k log lines per second on a laptop.

## Open decisions
- Final project name and repo location.
- License: Apache-2.0 for the core.

## Pull requests
- Before opening a PR or asking for review, bring `main` into the branch. The Claude review action only runs when the PR's copy of its own workflow file, `.github/workflows/claude-code-review.yml`, is identical to `main`'s; otherwise it skips with "Workflow validation failed" and still reports success. A PR that adds a different workflow file is still reviewed.
- The review runs when a PR is opened, reopened or marked ready for review, not on later pushes. To review new commits, convert the PR to draft and back to ready.
- Keep the PR title and description current with every commit in the PR. The title says what changed, not the branch name.
- Once a PR is merged, start follow-up work from a fresh `main`; don't stack new commits on the merged branch.

## Website (eunolabs.ai)
`site/` is the public page, deployed to Cloudflare Pages (see `site/README.md`). Keep it in sync with the product: when a change alters what eunox does, its scope, the classifications, supported gateways, the log format, licensing or status, update `site/public/index.html` in the same change. The page must not claim anything eunox doesn't do or plan to do. The terminal on the page is labelled sample output; keep it plausible against the real CLI once one exists.

## Working style
Be direct, don't patronize, and critique ideas rather than agreeing by default.
