# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**. Don't open a public issue.

Include the version or commit, what you found, and how to reproduce it. Don't include real access logs, client IPs or private paths; a minimal synthetic log line is enough.

You'll get an acknowledgement within a week. eunox is a small project, so fixes go into the latest release only.

## Scope

In scope: the `eunox` binary and crates in this repository, and the `ghcr.io/eunolabs/eunox` image. Examples: a crafted log line or signature header that crashes or stalls ingest, a signature accepted that shouldn't verify, a request classified `verified` or `ip-verified` when it isn't, or the report and metrics endpoints exposing more than they should.

Out of scope: the demo (`eunox-demo`, `docker-compose.yml` and `deploy/demo/`), which signs with a published test key on purpose, and vulnerabilities in nginx, Envoy or Kong themselves.
