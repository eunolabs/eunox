# eunox

Tells a site which AI agents are hitting it and which of them are who they claim to be. Anyone can put `GPTBot` in a user agent; eunox reads your gateway's access logs and checks each request's Web Bot Auth signature, the operator's published IP ranges and forward-confirmed reverse DNS. Every request gets one class: `verified`, `ip-verified`, `spoofed`, `unknown-bot` or `unclassified`.

Observe-only: nothing sits in the request path, so it adds no latency and can't break your traffic, and no data leaves your environment.

Status: v0. nginx, Envoy and Kong are supported, and `docker compose up` runs the whole thing as a demo. The operator side, `eunox sign`, is partly built. See the "v0 status" section of [docs/design.md](docs/design.md).

## Quickstart: the demo

```bash
docker compose up
```

Open http://localhost:8040/. A traffic generator sends requests through nginx and Envoy, both in front of a sample upstream, and the report fills within seconds:

- the demo agent comes out `verified`: it signs every request with Web Bot Auth and serves its own key directory, which the compose file adds as a source
- forged GPTBot, ClaudeBot and Googlebot user agents come out `spoofed`: the demo network isn't in any operator's published ranges
- `python-requests` and a Visa Trusted Agent Protocol-style `agent-payer-auth` signature come out `unknown-bot`
- browsers come out `unclassified`

Compose pulls the published image, `ghcr.io/eunolabs/eunox:main` (linux/amd64 and linux/arm64), and builds it from your checkout if the pull fails, which takes a few minutes the first time. `docker compose up --build` always builds from your checkout, for example after changing the code. `docker compose down` stops it. The demo agent signs with the RFC 9421 test key, whose private half is public, so never use it outside the demo.

## Run it on your site

With Docker:

```bash
docker run -p 5140:5140/udp -p 4317:4317 -p 8041:8041 -p 8040:8040 ghcr.io/eunolabs/eunox:main
```

`main` is built from every commit to the main branch, and also tagged `sha-<commit>`. Releases, once there are any, are tagged with their version and `latest`. To build the image yourself, run `docker build -t eunox .` and use `eunox` in place of the image name.

Or from source, with Rust 1.88 or later:

```bash
cargo build --release -p eunox
```

```bash
./target/release/eunox serve
```

Then point your gateway at it and reload:

- **nginx:** add the `log_format` and `access_log syslog:` lines from [docs/design.md](docs/design.md#inputs-what-each-gateway-logs), pointing at the eunox host's UDP port 5140. nginx's syslog is UDP only, so lines lost on the way aren't counted anywhere; the report says so. For exact counts, send the log through a shipper to `EUNOX_LINES_TCP`.
- **Envoy:** add the `access_log` block and the `eunox` cluster from the same section, pointing at the eunox host's port 4317 (OTLP over gRPC).
- **Kong:** enable the bundled `http-log` plugin from the same section, pointing at the eunox host's port 8041.

The report is at `http://<host>:8040/`, and `./target/release/eunox report` prints it in the terminal.

[docs/testing.md](docs/testing.md) walks through replaying a sample log and running against a local nginx, Envoy or Kong.

## Sign as an operator (early)

The other direction: if you run agents of your own, `eunox sign` makes you a Web Bot Auth operator with your own key and key directory.

```bash
eunox sign init --origin https://agent.example
```

This writes an Ed25519 key to `eunox-sign/keys/` (mode 0600, never printed) and `eunox-sign/sign.toml`. Then publish the directory at `https://agent.example/.well-known/http-message-signatures-directory`, either served:

```bash
eunox sign serve
```

behind your TLS terminator (port 8050; it signs each response, and only for `agent.example`), or as static files for a CDN, re-run before the printed expiry:

```bash
eunox sign export --out site
```

and sign a test request:

```bash
eunox sign request https://example.com/ --send
```

Built so far: the key, signed requests and the signed directory, following `draft-ietf-webbotauth-httpsig-protocol-01`. Not built yet: rotation, a key id per agent, and the sidecar and Playwright hook that sign on an agent's egress path so the agent process never holds the key. Until those exist, `eunox sign request` is for testing and registration. `eunox sign help` lists the options; the design is under "Operator side" in [docs/design.md](docs/design.md).

## Alerts

`/metrics` is Prometheus text; scrape port 8040. [deploy/prometheus/eunox-alerts.yml](deploy/prometheus/eunox-alerts.yml) has rules for a high share of spoofed agent traffic, a key directory or range file that stays down, log lines that stop parsing, and log lines that stop arriving. Add it under `rule_files:` and tune the thresholds to your traffic. `promtool test rules deploy/prometheus/eunox-alerts.test.yml` runs its tests.

## Configuration

Environment variables only; `eunox --help` lists them with their defaults.

## License

Apache-2.0.
