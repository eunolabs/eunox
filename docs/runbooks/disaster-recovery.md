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

## Post-Recovery Checklist

- [ ] All services healthy (`kubectl get pods -n eunox-system`)
- [ ] End-to-end token issuance and enforcement working
- [ ] Audit trail intact (no gaps)
- [ ] Monitoring/alerting functional
- [ ] Post-mortem scheduled within 48 hours
- [ ] Backup verification re-run
