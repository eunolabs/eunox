# Runbook: Disaster Recovery

**Severity**: P1 — Emergency  
**Last Updated**: 2026-05-26  
**Owner**: Platform Operations

## Overview

This runbook covers recovery procedures for catastrophic failures including data loss, total cluster failure, and regional outages.

## Recovery Point Objectives (RPO) / Recovery Time Objectives (RTO)

| Component                        | RPO               | RTO        | Backup Strategy                                     |
| -------------------------------- | ----------------- | ---------- | --------------------------------------------------- |
| Policy Database (Postgres)       | 1 hour            | 30 minutes | Continuous WAL archival + daily base backup         |
| Audit Ledger (Postgres)          | 1 hour            | 1 hour     | WAL archival (append-only, no point-in-time needed) |
| API Key Database (Postgres)      | 1 hour            | 30 minutes | Continuous WAL archival                             |
| Redis (Kill Switch / Revocation) | N/A (ephemeral)   | 5 minutes  | Rebuilt from source of truth on restart             |
| Signing Keys                     | N/A (static)      | 15 minutes | Stored in external secret manager                   |
| Configuration                    | N/A (declarative) | 15 minutes | Git (Helm values) + secret manager                  |

## Scenario 1: Single Service Failure

### Symptoms

- Pod CrashLoopBackOff
- Health check failures
- Error rate spike

### Recovery

```bash
# 1. Check pod status and events
kubectl -n eunox-system describe pod -l app.kubernetes.io/component=<service>

# 2. Check recent logs
kubectl -n eunox-system logs -l app.kubernetes.io/component=<service> --tail=100

# 3. If OOMKilled, increase memory limits
kubectl -n eunox-system patch deployment eunox-<service> \
  --type json -p '[{"op":"replace","path":"/spec/template/spec/containers/0/resources/limits/memory","value":"1Gi"}]'

# 4. If config issue, rollback
kubectl -n eunox-system rollout undo deployment/eunox-<service>

# 5. If persistent, cordon node and let scheduler reschedule
kubectl cordon <problematic-node>
kubectl -n eunox-system delete pod <pod-name>
```

## Scenario 2: Database Failure

### PostgreSQL Recovery from WAL

```bash
# 1. Identify last good backup
aws s3 ls s3://eunox-backups/postgres/base/ --recursive | tail -5

# 2. Restore base backup
pg_basebackup_restore --target=/var/lib/postgresql/data \
  --source=s3://eunox-backups/postgres/base/LATEST

# 3. Create recovery.conf for point-in-time recovery
cat > /var/lib/postgresql/data/recovery.conf <<CONF
restore_command = 'aws s3 cp s3://eunox-backups/postgres/wal/%f %p'
recovery_target_time = '2026-05-26 01:00:00 UTC'
CONF

# 4. Start PostgreSQL
pg_ctl start -D /var/lib/postgresql/data

# 5. Verify data integrity
psql -c "SELECT count(*) FROM api_keys;"
psql -c "SELECT max(created_at) FROM audit_events;"
```

### Redis Recovery

Redis state is ephemeral and rebuilt from authoritative sources:

```bash
# Kill switch state: reloaded from admin API on next toggle
# Revocation list: rebuilt from database on startup
# Call counters: reset (acceptable — counters are approximate)

# Simply restart Redis
kubectl -n eunox-system rollout restart statefulset/eunox-redis

# Verify gateway reconnects
kubectl -n eunox-system logs -l app.kubernetes.io/component=gateway --tail=20 | grep -i redis
```

## Scenario 3: Complete Cluster Loss

### Prerequisites

- Access to backup storage (S3/GCS/Azure Blob)
- Access to secret manager (Vault/KMS)
- Git repository with Helm values

### Recovery Steps

```bash
# 1. Provision new cluster (use IaC)
terraform apply -target=module.k8s_cluster

# 2. Install cert-manager, ingress controller, etc.
helm install cert-manager jetstack/cert-manager --set installCRDs=true

# 3. Restore secrets from external secret manager
# (Implementation depends on provider: Vault, AWS Secrets Manager, etc.)

# 4. Restore databases
# Follow "Database Failure" procedure above for each database

# 5. Deploy Eunox
helm install eunox k8s/helm/eunox/ \
  -f k8s/helm/eunox/values.yaml \
  -f k8s/helm/eunox/values-<cloud>.yaml \
  --set gateway.secretEnv.REDIS_URL=$REDIS_URL \
  # ... other secrets

# 6. Run smoke tests
./infra/smoke-test.sh

# 7. Update DNS / load balancer to point to new cluster
```

## Scenario 4: Compromised Signing Key

```bash
# 1. IMMEDIATELY activate kill switch (see kill-switch.md)
# 2. Rotate signing key (see key-rotation.md)
# 3. Revoke all tokens issued with compromised key
curl -X POST https://gateway.internal:3003/admin/v1/revocations/bulk \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "key_compromise", "issued_before": "2026-05-26T01:00:00Z"}'
# 4. Deactivate kill switch
# 5. Monitor for unauthorized access attempts
```

## Communication Template

```
INCIDENT: [Service/Component] failure
STATUS: [Investigating | Identified | Monitoring | Resolved]
IMPACT: [Description of user impact]
ETA: [Expected resolution time]
UPDATES: Every [15/30/60] minutes until resolved
```

## Scenario 5: Corrupted Audit HMAC Chain

### Symptoms

- Chain verification endpoint returns `chain_valid: false`
- Alert: `eunox_audit_chain_verification_failures > 0`
- Audit export returns errors for specific sequence ranges

### Diagnosis

```bash
# 1. Identify the break point
BREAK_POINT=$(curl -s https://gateway.internal:3003/admin/v1/audit/chain-proof \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" | jq '.first_invalid_sequence')

# 2. Inspect the corrupted record
psql -c "SELECT id, sequence_num, chain_hash, previous_hash
         FROM audit_records
         WHERE sequence_num = $BREAK_POINT
         ORDER BY sequence_num;"

# 3. Check if corruption is in a single record or a range
psql -c "SELECT sequence_num, chain_hash
         FROM audit_records
         WHERE sequence_num BETWEEN $((BREAK_POINT - 5)) AND $((BREAK_POINT + 5))
         ORDER BY sequence_num;"
```

### Recovery

**Option A: Restore from WAL backup (if corruption is recent)**

```bash
# 1. Identify the timestamp before corruption
CORRUPTION_TIME=$(psql -t -c "SELECT timestamp FROM audit_records WHERE sequence_num = $BREAK_POINT")

# 2. Restore to point-in-time before corruption (see Scenario 2)
# Use recovery_target_time slightly before $CORRUPTION_TIME

# 3. Verify chain integrity after restore
curl https://gateway.internal:3003/admin/v1/audit/chain-proof \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

**Option B: Anchor-based isolation (if corruption is older)**

```bash
# 1. Create anchors around the corrupted segment
# Anchor BEFORE the corrupted records
curl -X POST https://gateway.internal:3003/admin/v1/audit/anchor \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -d "{\"sequence_num\": $((BREAK_POINT - 1)), \"backend\": \"s3\"}"

# 2. Document the gap as a known integrity exception
# Add to the incident log with the sequence range and root cause

# 3. The chain continues validly from the next anchor forward
# Historical queries spanning the gap will note the integrity exception
```

**Option C: Full chain rebuild (last resort, requires HMAC secret)**

```bash
# WARNING: This recalculates all chain hashes. Only use if you have
# verified that record CONTENT (signatures) is intact and only the
# chain linkage is corrupted.

# 1. Stop all writers (gateway pods)
kubectl -n eunox-system scale deployment eunox-gateway --replicas=0

# 2. Run chain rebuild (custom migration script)
go run ./cmd/tools/rebuild-chain \
  --database-url="$AUDIT_DB_URL" \
  --hmac-secret="$AUDIT_HMAC_SECRET" \
  --start-sequence=1 \
  --dry-run=true  # Verify first

# 3. If dry-run looks correct, run for real
go run ./cmd/tools/rebuild-chain \
  --database-url="$AUDIT_DB_URL" \
  --hmac-secret="$AUDIT_HMAC_SECRET" \
  --start-sequence=1

# 4. Restart gateway
kubectl -n eunox-system scale deployment eunox-gateway --replicas=3

# 5. Verify
curl https://gateway.internal:3003/admin/v1/audit/chain-proof \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

---

## Scenario 6: Regional Outage (Multi-Region Failover)

### Prerequisites

- Active-passive or active-active multi-region deployment
- DNS failover configured (Route 53 health checks, Cloud DNS, or Traffic Manager)
- Cross-region database replication (RDS read replica, Cloud SQL cross-region)

### Symptoms

- Health check failures from the primary region
- Cloud provider status page confirms regional issue
- Increased latency from secondary region probes

### Failover Procedure

```bash
# 1. Confirm primary region is down (not just a transient issue)
# Wait for provider confirmation or 3+ minutes of continuous failure

# 2. Promote database read replica to primary
# AWS:
aws rds promote-read-replica --db-instance-identifier eunox-audit-dr-replica

# GCP:
gcloud sql instances promote-replica eunox-audit-dr-replica

# Azure:
az sql db failover --server eunox-dr --name eunox-audit --partner-server eunox-primary

# 3. Update service configuration to point to new database
kubectl -n eunox-system set env deployment/eunox-gateway \
  GATEWAY_AUDIT_DB_URL="$DR_DATABASE_URL"
kubectl -n eunox-system set env deployment/eunox-issuer \
  ISSUER_DB_URL="$DR_DATABASE_URL"

# 4. Update DNS (or let health-check-based failover handle it)
# Route 53:
aws route53 change-resource-record-sets --hosted-zone-id $ZONE_ID \
  --change-batch '{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"api.eunox.example.com","Type":"A","AliasTarget":{"HostedZoneId":"$DR_ALB_ZONE","DNSName":"$DR_ALB_DNS","EvaluateTargetHealth":true}}}]}'

# 5. Verify services are healthy in DR region
kubectl --context dr-cluster -n eunox-system get pods
./infra/smoke-test.sh

# 6. Verify audit chain continuity
# Note: There may be a gap if writes were in-flight during failover.
# This is acceptable — document the gap window.
curl https://gateway-dr:3003/admin/v1/audit/chain-proof \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"
```

### Failback Procedure

```bash
# 1. Confirm primary region is recovered
# 2. Re-establish replication from DR → primary
# 3. Wait for replication lag to reach zero
# 4. Perform controlled failover back to primary
# 5. Verify and update DNS
# 6. Re-establish DR replication (primary → DR)
```

---

## Scenario 7: HMAC Secret Compromise

### Symptoms

- Unauthorized party may have obtained the audit HMAC secret
- This enables them to forge chain hashes (but NOT record signatures)

### Impact Assessment

- **Chain integrity:** Compromised (attacker could insert/modify records
  with valid chain hashes)
- **Record signatures:** NOT compromised (signatures use KMS keys, not HMAC
  secret)
- **Detectability:** Forged records will lack valid KMS signatures

### Recovery

```bash
# 1. Immediately rotate the HMAC secret
# Follow: docs/runbooks/ledger-hmac-rotation.md

# 2. Verify all existing records have valid KMS signatures
# (HMAC may be forged, but signatures cannot be)
curl https://gateway.internal:3003/admin/v1/audit/verify-signatures \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY"

# 3. Create a new audit table with the new secret
# (Strategy A from ledger-hmac-rotation.md)

# 4. Mark the old chain as "pre-rotation" in monitoring
# Records with valid signatures are trustworthy regardless of HMAC state
```

---

## Backup Verification Schedule

| Check | Frequency | Automation |
|-------|-----------|------------|
| WAL archival lag | Continuous | CloudWatch/Stackdriver alarm |
| Base backup success | Daily | Backup job exit code monitoring |
| Restore test (full) | Monthly | Scheduled restore to test instance |
| Audit chain integrity | Hourly | Automated chain-proof endpoint check |
| DR region health | Every 5 min | Health check probes from primary |
| Secret manager access | Daily | Automated secret retrieval test |
| Helm values in git | On commit | CI validation |

---

## Post-Recovery Checklist

- [ ] All services healthy (`kubectl get pods -n eunox-system`)
- [ ] End-to-end token issuance and enforcement working
- [ ] Audit trail intact (no gaps, or gaps documented)
- [ ] HMAC chain verification passing
- [ ] Monitoring/alerting functional
- [ ] Redis state rebuilt (kill switch, revocations)
- [ ] Partner DID cache warm (federation working)
- [ ] Rate limiters reset (expected after restart)
- [ ] Post-mortem scheduled within 48 hours
- [ ] Backup verification re-run
- [ ] DR replication re-established (if failover occurred)
