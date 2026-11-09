# Testing eunox

From cheapest to closest to production. Every command runs from the repository root.

## 1. Automated tests

```bash
cargo test
```

- `core`: signature verification against Cloudflare's Web Bot Auth test vector and signatures built by hand from RFC 9421, and every classification rule.
- `directory`: fetching key directories and range files from a local HTTP server, key rotation and history, reverse DNS with a fixture resolver.
- `ingest`: every class through the pipeline, reverse-DNS paths, and the UDP, TCP and replay receivers over real sockets.
- `stats`: the rolling window, top paths and networks, the row cap, unknown signers.
- `eunox`: the whole service. A local key directory and range file, UDP syslog lines in, and `/report.txt`, `/metrics` and `/` checked over HTTP, including HTML escaping of request paths. This covers both v0 checks: a signed request shows as `verified`, a forged GPTBot as `spoofed`.

Throughput, one thread, no network:

```bash
cargo run --release -p eunox-ingest --example bench
```

## 2. Replay a log against live operator data

`testdata/sample.log` has one line per class, in the nginx log format from [design.md](design.md#inputs-what-each-gateway-logs). Its signed line is Cloudflare's test vector, signed with the RFC 9421 test key, which no operator publishes; serve `testdata/keys.json` as an extra key directory to verify it:

```bash
cargo build --release -p eunox
```

```bash
python3 -m http.server 8000 --bind 127.0.0.1 --directory testdata
```

In another terminal:

```bash
EUNOX_KEY_DIRECTORIES=demo=http://127.0.0.1:8000/keys.json ./target/release/eunox replay testdata/sample.log
```

Expected rows (the window ends at the log's own timestamp, 2025-01-01):

| agent | class | requests | why |
| --- | --- | --- | --- |
| GPTBot | spoofed | 2 | GPTBot user agent from 203.0.113.0/24, outside OpenAI's published ranges |
| demo | verified | 1 | the test-key signature, verified against the local key directory |
| GPTBot | ip-verified | 1 | 132.196.86.5, in OpenAI's published GPTBot ranges |
| Googlebot | ip-verified | 1 | 66.249.66.1, in Google's common-crawler ranges |
| python-requests | unknown-bot | 1 | generic automation user agent |
| (other) | unclassified | 1 | a browser |

Without `EUNOX_KEY_DIRECTORIES`, the signed line comes out `unknown-bot` (unknown signer). If an operator's file can't be fetched, the report lists it under warnings, and agents that depend on it come out `unknown-bot`, never `spoofed`.

The real-crawler IPs are taken from the operators' published lists; if a list changes, its line may stop being `ip-verified`.

## 3. Real nginx, locally

`testdata/nginx-local.conf` is a throwaway nginx on 127.0.0.1:8080 with the eunox `log_format`, sending syslog to 127.0.0.1:5140.

```bash
EUNOX_HTTP=127.0.0.1:8040 ./target/release/eunox serve
```

In another terminal:

```bash
mkdir -p /tmp/eunox-nginx && nginx -p /tmp/eunox-nginx -c "$PWD/testdata/nginx-local.conf"
```

```bash
curl -A 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' http://127.0.0.1:8080/pricing
```

```bash
curl -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' http://127.0.0.1:8080/
```

```bash
curl http://127.0.0.1:8080/api
```

```bash
./target/release/eunox report
```

Expected: GPTBot and Googlebot `spoofed` (127.0.0.1 is in neither operator's ranges, and it doesn't reverse-resolve under `googlebot.com`), curl `unknown-bot`. The report page is at http://127.0.0.1:8040/ and Prometheus metrics at http://127.0.0.1:8040/metrics.

Stop nginx with the same command plus `-s stop`.

A live request can't come out `verified` this way: the test vector's signature expired in 2025, and a fresh signature needs the test private key. The compose demo's traffic generator will sign fresh requests.

## 3b. Real Envoy, locally

`testdata/envoy-local.yaml` is a throwaway Envoy on 127.0.0.1:10000 that answers 200 itself and sends each request to eunox over OTLP on 127.0.0.1:4317, using the snippet from [design.md](design.md#inputs-what-each-gateway-logs).

```bash
EUNOX_HTTP=127.0.0.1:8040 EUNOX_OTLP_GRPC=127.0.0.1:4317 ./target/release/eunox serve
```

In another terminal:

```bash
docker run --rm --network host -v "$PWD/testdata/envoy-local.yaml:/etc/envoy/envoy.yaml:ro" envoyproxy/envoy:v1.32-latest
```

Send the same `curl` requests as for nginx, to port 10000, then run `./target/release/eunox report`. Expected: the same classes as with nginx. Signature headers arrive verbatim, so a request with `tag="agent-payer-auth"` is listed under signed by unknown keys or schemes.

## 3c. Kong, locally

`testdata/kong-local.yaml` is a DB-less Kong on 127.0.0.1:8000 with the `http-log` plugin pointing at eunox on 127.0.0.1:8041. Run against Kong 3.9.4: 151 of 151 log lines parsed, signed requests came out `verified` and forged crawler user agents `spoofed`.

```bash
EUNOX_HTTP=127.0.0.1:8040 EUNOX_KONG_HTTP=127.0.0.1:8041 ./target/release/eunox serve
```

In another terminal:

```bash
docker run --rm --network host -e KONG_DATABASE=off -e KONG_DECLARATIVE_CONFIG=/kong.yaml -e KONG_PROXY_LISTEN=127.0.0.1:8000 -e KONG_ADMIN_LISTEN=off -v "$PWD/testdata/kong-local.yaml:/kong.yaml:ro" kong:3.9
```

Send the same `curl` requests as for nginx, to port 8000, then run `./target/release/eunox report`. The plugin batches for up to a second, so wait a moment. Expected: the same classes as with nginx.

For signed traffic too, run the demo generator against Kong. It serves its key directory on 127.0.0.1:8090, so start eunox with that directory as an extra source:

```bash
DEMO_TARGETS=http://127.0.0.1:8000 DEMO_LISTEN=127.0.0.1:8090 DEMO_DIRECTORY_URL=http://127.0.0.1:8090/.well-known/http-message-signatures-directory ./target/release/eunox-demo
```

```bash
EUNOX_HTTP=127.0.0.1:8040 EUNOX_KONG_HTTP=127.0.0.1:8041 EUNOX_KEY_DIRECTORIES=demo=http://127.0.0.1:8090/.well-known/http-message-signatures-directory ./target/release/eunox serve
```

Expected: `demo` `verified`; forged GPTBot, ClaudeBot and Googlebot `spoofed`; `python-requests` and the `agent-payer-auth` signature `unknown-bot`. Requests in the first second or two, before the directory and ranges have loaded, come out `unknown-bot` or as an unknown signer: missing data never produces `spoofed`.

With a route that has `strip_path: true`, Kong logs the rewritten path as `upstream_uri` and keeps the client's path in `request.uri`, which is the one eunox reads. The `live_kong_strip_path_keeps_the_client_path` test in `crates/ingest/src/kong.rs` pins this with a payload captured from Kong 3.9.4.

## 3d. OTLP metrics into an OpenTelemetry Collector

A Collector with an OTLP receiver on 127.0.0.1:4319 and the `debug` exporter prints every metric eunox pushes:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4319
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [debug]
```

Run the Collector with that config (as `otelcol --config FILE`, or the `otel/opentelemetry-collector` image), then:

```bash
EUNOX_HTTP=127.0.0.1:8040 EUNOX_OTLP_GRPC=off EUNOX_OTLP_METRICS_ENDPOINT=http://127.0.0.1:4319 EUNOX_OTLP_METRICS_INTERVAL_SECS=5 ./target/release/eunox serve
```

Send any request through a local gateway from the sections above. Within about five seconds the Collector logs `eunox.requests` as a cumulative monotonic sum with `class` and `agent` attributes, `eunox.window.requests` with one point per class, and the `eunox.ingest.*` counters.

## 4. On a real site

1. Add the `log_format` and an `access_log syslog:` line from [design.md](design.md#inputs-what-each-gateway-logs) to the site's nginx, pointing at the host running eunox, and reload.
2. Run `eunox serve` there. Defaults: syslog on UDP 5140, report on 8040. See `eunox --help` for the environment variables.
3. If nginx is behind a CDN or load balancer, configure `real_ip` (`set_real_ip_from`, `real_ip_header`) first, or `$remote_addr` is the proxy and every real crawler comes out `spoofed`.
4. Check the report's warnings: parse errors mean the log format doesn't match; a source "not loaded" means eunox can't reach that operator's file.

Replay only works on logs written in the eunox JSON format; nginx's default `combined` format has no signature headers. Start logging in the eunox format now to have history to replay later.

Reverse DNS needs a working resolver on the eunox host. Set `EUNOX_RDNS=off` where DNS isn't available; agents verified only by reverse DNS then come out `unknown-bot`.

## 5. The compose demo

Everything at once, from the repository root:

```bash
docker compose up
```

- **`traffic`** (`eunox-demo`) serves a key directory for the RFC 9421 test key and sends requests through both gateways: freshly signed ones (with a `Signature-Agent` naming its directory), forged GPTBot, ClaudeBot and Googlebot, an `agent-payer-auth` signature, `python-requests` and browsers.
- **`eunox`** has the demo directory added as a source (`EUNOX_KEY_DIRECTORIES`), on top of the built-in operators.
- **`nginx`** (port 8080) and **`envoy`** (port 10000) proxy to **`upstream`** and send their logs to eunox, with the configs in `deploy/demo/`.

Open http://localhost:8040/. Expected within seconds:

| agent | class | why |
| --- | --- | --- |
| demo | verified | signed with the test key, verified against the demo directory |
| GPTBot, ClaudeBot | spoofed | the demo network isn't in OpenAI's or Anthropic's published ranges |
| Googlebot | spoofed, or unknown-bot | spoofed when the container's resolver answers reverse DNS; unknown-bot when DNS gets no answer |
| python-requests, unknown signer (`agent-payer-auth`) | unknown-bot | generic automation client; unsupported signature scheme |
| (other) | unclassified | browsers |

Both gateways appear in the counts: the generator sends the same mix through each.

Compose runs the published image, `ghcr.io/eunolabs/eunox:main`, when it can pull it, so to test changes in your checkout use `docker compose up --build`. To check that the image still builds for both platforms, as the `image` workflow does on pull requests that touch the Dockerfile or `Cargo.lock`:

```bash
docker buildx build --platform linux/amd64,linux/arm64 .
```

The arm64 half cross-compiles in the build stage, so it needs no emulation. The default builder can build both platforms only with the containerd image store (`docker info` shows `driver-type: io.containerd.snapshotter.v1`). Otherwise, create a builder first with `docker buildx create --use`.

## 6. `eunox sign`, locally

`cargo test -p eunox-core --test sign` checks the signer byte for byte against the test vectors in `draft-ietf-webbotauth-httpsig-protocol-01` (Appendix E.2.1 for a request, E.2.3 for the signed directory response). `cargo test -p eunox --test sign` runs `init`, serves the directory on localhost and replays a request signed by `eunox sign` through eunox with that directory as its only key source; it comes out `verified`.

By hand, with a throwaway state directory:

```bash
./target/release/eunox sign init --origin https://agent.example --dir /tmp/op
```

```bash
./target/release/eunox sign serve --dir /tmp/op --listen 127.0.0.1:8050 &
```

```bash
curl -si -H 'Host: agent.example' http://127.0.0.1:8050/.well-known/http-message-signatures-directory
```

The response carries the media type, `Cache-Control`, `Content-Digest` and one `binding` signature per key. Any other `Host` gets 421. `eunox sign request https://example.com/ --dir /tmp/op` prints the three request headers; add `--send` to send them.

## Not testable yet

- **`eunox sign` against a third-party verifier:** needs the directory published on a real HTTPS origin and, for Cloudflare, the agent registered in its directory.
- **A real agent's signature:** the demo verifies its own test key; a real `verified` needs traffic from an operator that publishes a key directory (OpenAI, Google).
