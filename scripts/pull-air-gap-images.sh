#!/bin/sh
# scripts/pull-air-gap-images.sh
#
# Download all images listed in k8s/air-gap-images.txt and optionally retag
# them for a private registry.  Designed for air-gapped on-prem deployments
# where ghcr.io is not reachable from the cluster.
#
# Usage
# -----
#   # Download and retag for a private registry (set PRIVATE_REGISTRY first):
#   PRIVATE_REGISTRY=registry.internal:5000 sh scripts/pull-air-gap-images.sh
#
#   # Download only (no retag, no push):
#   sh scripts/pull-air-gap-images.sh --pull-only
#
#   # Verify that all images are already present locally (no pull):
#   sh scripts/pull-air-gap-images.sh --verify-only
#
#   # Save all images to a tar archive for offline transport:
#   sh scripts/pull-air-gap-images.sh --save-tar air-gap-bundle.tar
#
#   # Load a previously saved tar archive into Docker:
#   docker load -i air-gap-bundle.tar
#
# Environment variables
#   PRIVATE_REGISTRY   — private registry host[:port] to retag and push images
#                        to (e.g. registry.internal:5000).  Omit to skip retag.
#   IMAGE_LIST_FILE    — path to the image list file.
#                        Default: k8s/air-gap-images.txt (relative to repo root).
#
# Exit codes
#   0  — all images pulled (and retagged/pushed) successfully
#   1  — one or more images failed
#
# Requirements
#   docker  — must be installed and the daemon must be accessible.

set -u

# ── Defaults ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMAGE_LIST_FILE="${IMAGE_LIST_FILE:-${REPO_ROOT}/k8s/air-gap-images.txt}"
PRIVATE_REGISTRY="${PRIVATE_REGISTRY:-}"

PULL_ONLY=false
VERIFY_ONLY=false
SAVE_TAR=""

# ── Argument parsing ──────────────────────────────────────────────────────────

while [ $# -gt 0 ]; do
  case "$1" in
    --pull-only)    PULL_ONLY=true; shift ;;
    --verify-only)  VERIFY_ONLY=true; shift ;;
    --save-tar)
      SAVE_TAR="${2:?'--save-tar requires a path argument'}"; shift 2 ;;
    *)
      printf "Unknown argument: %s\n" "$1" >&2
      exit 1
      ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────────

if [ ! -f "$IMAGE_LIST_FILE" ]; then
  printf "ERROR: image list not found: %s\n" "$IMAGE_LIST_FILE" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  printf "ERROR: docker is not installed or not in PATH\n" >&2
  exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

PASS=0
FAIL=0
IMAGES_PULLED=""

ok()   { printf "[PASS] %s\n" "$1"; PASS=$((PASS + 1)); }
fail() { printf "[FAIL] %s\n" "$1" >&2; FAIL=$((FAIL + 1)); }

# Strip comment lines and blank lines from the image list.
images() {
  grep -v '^\s*#' "$IMAGE_LIST_FILE" | grep -v '^\s*$'
}

# ── Main loop ─────────────────────────────────────────────────────────────────

printf "=== Euno Air-Gap Image Tool ===\n"
printf "Image list: %s\n" "$IMAGE_LIST_FILE"
if [ -n "$PRIVATE_REGISTRY" ]; then
  printf "Private registry: %s\n" "$PRIVATE_REGISTRY"
fi
printf "\n"

while IFS= read -r image; do
  # Each line is: <ref>@<digest>  (or just <ref> without a digest pin)
  # Strip the digest part to get the pull reference; keep the full string
  # for digest verification.
  pull_ref="$image"

  if $VERIFY_ONLY; then
    # Check if the image is already present locally.
    if docker image inspect "$pull_ref" >/dev/null 2>&1; then
      ok "Present locally: $pull_ref"
    else
      fail "Not found locally: $pull_ref"
    fi
    continue
  fi

  # Pull the image.
  if docker pull "$pull_ref" >/dev/null 2>&1; then
    ok "Pulled: $pull_ref"
    IMAGES_PULLED="$IMAGES_PULLED $pull_ref"
  else
    fail "Failed to pull: $pull_ref"
    continue
  fi

  $PULL_ONLY && continue

  # Retag and push to the private registry when PRIVATE_REGISTRY is set.
  if [ -n "$PRIVATE_REGISTRY" ]; then
    # Derive the target tag: strip the source registry hostname and any digest.
    # e.g. ghcr.io/edgeobs/euno/tool-gateway:1.0.0@sha256:... →
    #      registry.internal:5000/edgeobs/euno/tool-gateway:1.0.0
    stripped=$(printf '%s' "$pull_ref" | sed 's|@sha256:[a-f0-9]*$||')
    # Remove the source registry hostname (everything up to and including the
    # first '/') only when the first component contains a '.' or ':' (i.e. it
    # is a registry host, not a bare image name like "node:20-alpine").
    first_component=$(printf '%s' "$stripped" | cut -d'/' -f1)
    case "$first_component" in
      *.*|*:*)
        path=$(printf '%s' "$stripped" | cut -d'/' -f2-)
        ;;
      *)
        path="$stripped"
        ;;
    esac
    target="${PRIVATE_REGISTRY}/${path}"

    if docker tag "$stripped" "$target" >/dev/null 2>&1 && \
       docker push "$target" >/dev/null 2>&1; then
      ok "Retagged and pushed: $target"
    else
      fail "Failed to retag/push: $target"
    fi
  fi
done <<EOF
$(images)
EOF

# ── Save tar (optional) ───────────────────────────────────────────────────────

if [ -n "$SAVE_TAR" ] && [ -n "$IMAGES_PULLED" ]; then
  printf "\n-- Saving tar archive --\n"
  # shellcheck disable=SC2086
  if docker save $IMAGES_PULLED -o "$SAVE_TAR" >/dev/null 2>&1; then
    ok "Saved: $SAVE_TAR"
  else
    fail "Failed to save tar: $SAVE_TAR"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

printf "\n=== Results: %d passed, %d failed ===\n" "$PASS" "$FAIL"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
