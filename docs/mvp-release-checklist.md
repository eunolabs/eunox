# eunox-mcp MVP Release Checklist

**Target binary:** `eunox-mcp`  
**Release tool:** [GoReleaser](https://goreleaser.com) + GitHub Actions  
**Registries:** `ghcr.io/eunolabs/eunox-mcp` and `eunolabs/eunox-mcp` (Docker Hub)

Work through every section in order. Each item has a checkbox — tick it as you go.

---

## Stage 1 — Code quality

### 1.1 License headers

Every `.go` file must carry the Apache-2.0 SPDX header.

```bash
make check-license
```

Expected: `All files have correct license headers.`

- [x] `make check-license` exits 0

### 1.2 Static analysis

```bash
make vet      # go vet — catches obvious issues fast
make lint     # golangci-lint — full ruleset (installs lint binary on first run)
```

- [x] `make vet` exits 0 with no output
- [x] `make lint` exits 0 with no warnings

### 1.3 Unit + integration tests with race detector

```bash
make test
```

This runs `go test -race -count=1 ./...` across every package. Expect ~30 s on a laptop.

- [x] All tests pass
- [x] No data-race warnings printed

### 1.4 Coverage gate (pkg/)

```bash
make coverage
```

The CI gate requires ≥ 80 % average coverage across `pkg/`. Check the last line printed.

- [x] `pkg/` average coverage ≥ 80 %

### 1.5 Condition-type constants test

Verify that every condition type constant is non-empty camelCase and round-trips correctly through JSON and `ConditionWrapper`.

```bash
go test ./pkg/capability/ -run 'TestConditionTypeConstantsValid|TestAllConditionTypesHaveHandlers' -v -count=1
```

- [x] All subtests pass

---

## Stage 2 — Build verification

### 2.1 Local binary build

```bash
make build            # produces bin/eunox-mcp for your host platform
./bin/eunox-mcp --help
```

- [x] Binary compiles without error
- [x] `--help` output is readable

### 2.2 Cross-platform compilation

Verify the release matrix compiles cleanly before tagging.

```bash
for GOOS in linux darwin windows; do
  for GOARCH in amd64 arm64; do
    echo "--- $GOOS/$GOARCH ---"
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -o /dev/null ./cmd/mcp
  done
done
```

- [x] All 6 platform combinations exit 0

### 2.3 Docker image (local platform)

```bash
make docker-build-mcp VERSION=0.1.0
docker run --rm eunolabs/eunox-mcp:0.1.0 --help
```

- [x] Image builds successfully
- [x] `--help` output appears (confirms entrypoint is wired correctly)

---

## Stage 3 — End-to-end testing

### Prerequisites

```
docker >= 24.0
docker compose >= 2.20
curl, jq
```

### 3a — Manifest-only mode

**Start the stack:**

```bash
make -C demo up
```

Wait for all three containers to appear healthy:

```
✔ Container demo-mock-mcp-server-1  Started
✔ Container demo-keycloak-1         Started
✔ Container demo-eunox-mcp-1        Started
```

**Allowed call — `read_file /reports/q3.pdf`:**

```bash
make -C demo allow
```

Expected: `"isError": false` and mock file contents in the response.

- [x] Allow response contains `"isError": false`

**Denied call — `write_file` (not in manifest):**

```bash
make -C demo deny
```

Expected: `"isError": true` and `"code":"AUTHORIZATION_FAILED"`.

- [x] Deny response contains `AUTHORIZATION_FAILED`

**Denied call — `read_file /etc/shadow` (wrong path):**

```bash
make -C demo deny-path
```

Expected: `"isError": true` and `"code":"CONDITION_FAILED"` with `"argument":"path"` in details.

- [x] Deny response contains `CONDITION_FAILED`

**Denied call — `query_db DELETE` (wrong SQL op):**

```bash
make -C demo deny-op
```

Expected: `"isError": true` and `"code":"CONDITION_FAILED"` with `"allowedOperations"` in details.

- [x] Deny response contains `CONDITION_FAILED`

**Audit log — verify records and HMAC chain:**

```bash
make -C demo audit   # Ctrl-C after a few records appear
```

Each record should have a `"hmac": "sha256:..."` field.

```bash
docker run --rm \
  -v "$(pwd)/demo/audit:/audit" \
  --entrypoint /usr/local/bin/mcp \
  eunolabs/eunox-mcp:latest \
  validate-token \
  --audit-log /audit/audit.jsonl \
  --audit-key-path /audit/audit.key
```

Expected: `Checked N record(s): N valid, 0 invalid, 0 skipped.`

- [ ] Audit records stream correctly
- [ ] HMAC validation passes

**CI integration test (full automated run):**

```bash
make -C demo ci-test
```

This starts the stack, runs all assertions from `demo/scripts/ci-test.sh`, and tears down. Expect `Results: 9 passed, 0 failed`.

- [x] `ci-test` exits 0 with 8/8 passing

### 3b — JWT mode (manifest + IdP claims)

**Switch to JWT mode:**

```bash
make -C demo down     # tear down manifest-only stack first
make -C demo up-jwt   # starts Keycloak + eunox-mcp in JWT mode
```

Keycloak takes up to 30 s to start. The `--wait` flag will block until it's healthy.

**Fetch a test JWT:**

```bash
make -C demo jwt
```

Paste the printed token into [jwt.io](https://jwt.io) and verify the claims include:

- `"eunox.capabilities": ["read_file:/reports/*", "query_db:SELECT"]`
- `"aud": "eunox"`

- [ ] JWT decode shows expected `eunox.capabilities` claims

**JWT-authenticated allowed call:**

```bash
make -C demo jwt-allow
```

Expected: `"isError": false`.

- [ ] JWT-allow response contains `"isError": false`

**JWT-authenticated denied call (`write_file` absent from JWT claims):**

```bash
make -C demo jwt-deny
```

Expected: `"isError": true` and `AUTHORIZATION_FAILED`.

- [ ] JWT-deny response contains `AUTHORIZATION_FAILED`

**Full JWT CI test:**

```bash
make -C demo down
make -C demo ci-test-jwt
```

- [ ] `ci-test-jwt` exits 0

**Tear down:**

```bash
make -C demo down
```

---

## Stage 4 — Documentation review

- [ ] `README.md` — quick-start commands match current CLI flags; version references are current
- [ ] `docs/capability-manifest-guide.md` — all 11 condition types are documented
- [ ] `docs/threat-model-mcp.md` — Stage 1 gates are consistent with enforcement engine
- [ ] `docs/benchmarks.md` — numbers are not wildly out of date
- [ ] `demo/README.md` — step-by-step walkthrough matches what `make -C demo up` actually produces
- [ ] `NOTICE` — copyright year and attributions are correct
- [ ] `cmd/mcp/LICENSE` — Apache-2.0, correct year

---

## Stage 5 — Release preparation

### 5.1 Decide the version number

Follow [Semantic Versioning](https://semver.org): `vMAJOR.MINOR.PATCH`.  
For the first public MVP use `v0.1.0`.

### 5.2 Ensure `main` is clean

```bash
git checkout main
git pull origin main
git status            # must be clean — no uncommitted changes
git log --oneline -5  # confirm the tip commit is what you want to release
```

- [ ] On `main` branch
- [ ] Working tree is clean
- [ ] Tip commit is the intended release commit

### 5.3 Check GitHub Actions status

Go to `https://github.com/eunolabs/eunox/actions` and confirm the most recent `Go CI` and `Demo Integration Tests` runs on `main` are green.

- [ ] Go CI (lint + test + build + benchmark) — green
- [ ] Demo Integration Tests (manifest-only + JWT mode) — green

### 5.4 Verify Docker Hub and GHCR secrets

The Docker publish workflow requires these repository secrets:

| Secret               | Where used                                  |
| -------------------- | ------------------------------------------- |
| `DOCKERHUB_USERNAME` | `docker/login-action` for Docker Hub        |
| `DOCKERHUB_TOKEN`    | Docker Hub access token (not password)      |
| `GITHUB_TOKEN`       | Auto-provided by Actions for `ghcr.io` push |

Go to `Settings → Secrets and variables → Actions` and confirm `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` are set.

- [ ] `DOCKERHUB_USERNAME` secret is present
- [ ] `DOCKERHUB_TOKEN` secret is present

---

## Stage 6 — Tag and publish

### 6.1 Create and push the semver tag

```bash
git tag -a v0.1.0 -m "Release v0.1.0 — MVP"
git push origin v0.1.0
```

This single `git push` triggers three workflows in parallel:

| Workflow         | File                                   | Triggered by | Output                      |
| ---------------- | -------------------------------------- | ------------ | --------------------------- |
| `Go Publish`     | `.github/workflows/go-publish.yml`     | `v*.*.*` tag | GitHub Release + pkg.go.dev |
| `Docker Publish` | `.github/workflows/docker-publish.yml` | `v*.*.*` tag | Docker Hub + GHCR images    |
| (standard CI)    | `.github/workflows/ci.yml`             | any push     | lint / test / build         |

- [ ] Tag pushed without error

### 6.2 Monitor the workflows

Go to `https://github.com/eunolabs/eunox/actions` and watch all three workflows complete.

- [ ] `Go Publish` — passes `go mod verify`, tests, and creates the GitHub Release
- [ ] `Docker Publish` — builds `linux/amd64` + `linux/arm64` images, pushes to Docker Hub and GHCR; Windows `amd64` image pushed with `-windows` suffix
- [ ] GitHub Release page at `https://github.com/eunolabs/eunox/releases` shows `v0.1.0` with auto-generated release notes

---

## Stage 7 — Post-release verification

### 7.1 Verify `go install`

On a machine that does **not** have the repo checked out (or in a clean `$GOPATH`):

```bash
go install github.com/eunolabs/eunox/cmd/mcp@v0.1.0
$(go env GOPATH)/bin/mcp --version
```

Expected output includes `v0.1.0`.

- [ ] `go install` succeeds from the published tag
- [ ] Version string matches `v0.1.0`

### 7.2 Verify Docker images

```bash
# Linux image (GHCR)
docker pull ghcr.io/eunolabs/eunox-mcp:0.1.0
docker run --rm ghcr.io/eunolabs/eunox-mcp:0.1.0 --version

# Linux image (Docker Hub)
docker pull eunolabs/eunox-mcp:0.1.0
docker run --rm eunolabs/eunox-mcp:0.1.0 --version

# latest tag resolves to 0.1.0
docker pull ghcr.io/eunolabs/eunox-mcp:latest
docker run --rm ghcr.io/eunolabs/eunox-mcp:latest --version
```

- [ ] `ghcr.io/eunolabs/eunox-mcp:0.1.0` pulls and runs
- [ ] `eunolabs/eunox-mcp:0.1.0` pulls and runs
- [ ] `latest` tag resolves correctly

### 7.3 Run the full demo from the published image

Replace the local build with the published image to confirm the release is functional end-to-end.

```bash
# edit demo/docker-compose.yml temporarily: replace build: ... with
#   image: ghcr.io/eunolabs/eunox-mcp:0.1.0
make -C demo ci-test
```

- [ ] `ci-test` passes 9/9 using the published image

### 7.4 Verify pkg.go.dev indexing

Visit `https://pkg.go.dev/github.com/eunolabs/eunox/cmd/mcp@v0.1.0`. It may take a few minutes to index. Trigger manually if needed:

```bash
curl "https://sum.golang.org/lookup/github.com/eunolabs/eunox/cmd/mcp@v0.1.0"
```

- [ ] Module appears on pkg.go.dev (allow up to 10 min)

---

## Rollback procedure

If a critical defect is found after tagging:

1. **Do not delete the tag** — `go install` users and Docker users may already have it cached.
2. Create a patch release instead: fix → commit → tag `v0.1.1`.
3. If the release must be hidden: mark the GitHub Release as a pre-release draft, then publish `v0.1.1` as the stable release.

---

## Quick reference

| Task                  | Command                                                |
| --------------------- | ------------------------------------------------------ |
| Full local validation | `make all` (lint + test + build)                       |
| Coverage report       | `make coverage`                                        |
| Demo stack (manifest) | `make -C demo up`                                      |
| Demo stack (JWT mode) | `make -C demo up-jwt`                                  |
| Demo CI tests         | `make -C demo ci-test && make -C demo ci-test-jwt`     |
| Tear down demo        | `make -C demo down`                                    |
| Publish release       | `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z` |
