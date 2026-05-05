# Operational scripts

## `verify-evidence.js` — F-9 continuous evidence-chain verification

Wraps `AuditEvidenceSigner.verifyEvidence` from `packages/common/src/evidence.ts`
in a batch-oriented entry point so the previous interval's signed audit
evidence can be re-checked on a schedule. Running this on a daily cron
catches log tampering automatically.

### Inputs

The script accepts one or more arguments — each may be:

* a JSON file containing a single `SignedAuditEvidence` record;
* a JSON file containing an array of records (the shape produced by
  `kubectl logs --output=json | jq -s .` and similar pipelines);
* a JSONL / NDJSON file (one record per line — the shape produced by the
  Winston file transport and most cloud log exporters);
* a directory (walked one level deep for `*.json`, `*.jsonl`, `*.ndjson`);
* the literal `-`, meaning "read from stdin".

### Configuration

The verifier holds **only the public key** so a compromised verification
host cannot mint new evidence. Configure via environment variables:

| Variable                              | Description                                                                                 |
| ------------------------------------- | ------------------------------------------------------------------------------------------- |
| `EVIDENCE_VERIFY_PUBLIC_KEY_PEM`      | Inline PEM string for the verifier's public key.                                            |
| `EVIDENCE_VERIFY_PUBLIC_KEY_FILE`     | Path to a PEM file on disk.                                                                 |
| `EVIDENCE_SIGNING_PUBLIC_KEY_{PEM,FILE}` | Fallback for hosts that already configure the signing-side public key.                  |
| `EVIDENCE_VERIFY_ALGORITHM`           | JWS algorithm: `RS256` (default), `PS256`, `ES256`, `EdDSA`. Falls back to `EVIDENCE_SIGNING_ALGORITHM`. |
| `EVIDENCE_VERIFY_KEY_ID`              | When set, pin verification to that `kid`; records claiming a different `kid` are rejected. Falls back to `EVIDENCE_SIGNING_KEY_ID`. |

If no public key env var is set the script exits `2` (configuration
error) so a misconfigured cron job is loud rather than silently passing.

### Exit codes & alerting

| Code | Meaning                                                            |
| ---- | ------------------------------------------------------------------ |
| `0`  | All records verified.                                              |
| `1`  | At least one record failed verification — **alert**.               |
| `2`  | Usage / configuration error.                                       |

A machine-readable JSON report (`{ total, verified, failed, failures, … }`)
is written to stdout for runs that actually process input records,
suitable for piping into Sentinel, PagerDuty, or any webhook-driven
alerting system. Usage / configuration exits (`--help`, unknown flags,
no inputs, missing verifier configuration — all exit `2`) print
human-readable text on stderr/stdout instead of a JSON report.

By default the job stops on the first failure so the alert fires as
quickly as possible. Pass `--all` for a forensic run that walks the full
batch and reports every offender.

### Examples

```sh
# Build the common package once so the script can resolve the impl.
npm run build -w @euno/common

# Verify a single record (matches Sprint-5 pilot G10).
EVIDENCE_VERIFY_PUBLIC_KEY_FILE=/etc/euno/audit-pub.pem \
  node scripts/verify-evidence.js sample-evidence.json

# Daily cron over yesterday's exported batch directory.
# (GNU `date` syntax — on macOS/BSD use `date -u -v-1d +%F`.)
EVIDENCE_VERIFY_PUBLIC_KEY_FILE=/etc/euno/audit-pub.pem \
  node scripts/verify-evidence.js /var/log/euno/audit/$(date -u -d 'yesterday' +%F)

# Stream from stdin.
zcat audit-batch.jsonl.gz | \
  EVIDENCE_VERIFY_PUBLIC_KEY_FILE=/etc/euno/audit-pub.pem \
  node scripts/verify-evidence.js -
```

### Scheduling

A typical Kubernetes `CronJob` runs the script once per day, mounts the
public key as a read-only secret, and pipes the JSON report to whatever
sink raises the alert (e.g. an Azure Monitor data collection rule). Any
non-zero exit must page the on-call.
