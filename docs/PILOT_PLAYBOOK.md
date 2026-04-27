# Pilot Playbook - Euno Capability-Native Agent Governance

## Overview

This playbook provides step-by-step guidance for the operational team to deploy, monitor, and support the Euno system during the pilot phase.

**Target Audience:** Operations team, DevOps engineers, SREs, support staff

**Pilot Duration:** 4-8 weeks

**Last Updated:** 2026-04-27

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Deployment Procedures](#deployment-procedures)
3. [Monitoring and Dashboards](#monitoring-and-dashboards)
4. [Error Interpretation](#error-interpretation)
5. [Common Issues and Troubleshooting](#common-issues-and-troubleshooting)
6. [Support Contacts](#support-contacts)
7. [Daily Operations Checklist](#daily-operations-checklist)
8. [Metrics and Success Criteria](#metrics-and-success-criteria)

---

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] **Azure Subscription** with appropriate permissions
  - [ ] Azure AD tenant configured
  - [ ] Azure Key Vault created
  - [ ] AKS cluster provisioned (or access to existing cluster)
  - [ ] Azure Monitor / Log Analytics workspace ready

- [ ] **Kubernetes Cluster** (AKS recommended)
  - [ ] Version 1.25 or higher
  - [ ] Pod Security Standards enabled
  - [ ] AppArmor support enabled on nodes
  - [ ] Network policies supported (Calico or Azure Network Policy)

- [ ] **Secrets Management**
  - [ ] Azure Key Vault signing key created
  - [ ] Admin API key generated and stored securely
  - [ ] Azure AD client credentials obtained
  - [ ] Kubernetes Secrets created for sensitive values

### Configuration Verification

- [ ] **Environment Variables** configured in ConfigMaps
  ```bash
  kubectl get configmap -n euno-system issuer-config -o yaml
  kubectl get configmap -n euno-system gateway-config -o yaml
  ```

- [ ] **Secrets** properly referenced
  ```bash
  kubectl get secrets -n euno-system
  # Should see: issuer-secrets, gateway-secrets
  ```

- [ ] **Network Policies** applied
  ```bash
  kubectl get networkpolicies -n euno-system
  # Should see policies for issuer, gateway, agent-runtime
  ```

- [ ] **Pod Security Standards** enforced
  ```bash
  kubectl get namespace euno-system -o jsonpath='{.metadata.labels}'
  # Should include: pod-security.kubernetes.io/enforce=restricted
  ```

### Security Hardening Verification

- [ ] **AppArmor Profiles** loaded on all nodes
  ```bash
  # Run on each node
  sudo apparmor_status | grep euno-restricted
  ```

- [ ] **SELinux Policies** installed (if using SELinux)
  ```bash
  sudo semodule -l | grep euno
  ```

- [ ] **Resource Quotas** applied
  ```bash
  kubectl get resourcequota -n euno-system
  ```

- [ ] **Non-Root Users** verified
  ```bash
  kubectl get pods -n euno-system -o json | \
    jq '.items[].spec.securityContext.runAsNonRoot'
  # All should be: true
  ```

---

## Deployment Procedures

### Step 1: Create Namespace and Apply Security Policies

```bash
# Create namespace with Pod Security Standards
kubectl apply -f k8s/pod-security-standards.yaml

# Verify namespace created
kubectl get namespace euno-system
```

### Step 2: Install AppArmor Profiles (On Each Node)

```bash
# Copy profile to nodes
for node in $(kubectl get nodes -o name); do
  kubectl cp k8s/security-policies/apparmor-profile.conf $node:/tmp/euno-restricted
done

# Load profiles on each node
for node in $(kubectl get nodes -o name); do
  kubectl exec -it $node -- bash -c \
    "sudo cp /tmp/euno-restricted /etc/apparmor.d/ && \
     sudo apparmor_parser -r /etc/apparmor.d/euno-restricted"
done
```

### Step 3: Create Secrets

**DO NOT commit secrets to git. Store in Azure Key Vault or secret management system.**

```bash
# Create issuer secrets
kubectl create secret generic issuer-secrets \
  --from-literal=azure-client-id="${AZURE_CLIENT_ID}" \
  --from-literal=azure-client-secret="${AZURE_CLIENT_SECRET}" \
  --from-literal=azure-tenant-id="${AZURE_TENANT_ID}" \
  --namespace=euno-system

# Create gateway secrets
kubectl create secret generic gateway-secrets \
  --from-literal=admin-api-key="${ADMIN_API_KEY}" \
  --namespace=euno-system

# Verify secrets created
kubectl get secrets -n euno-system
```

### Step 4: Apply Network Policies

```bash
kubectl apply -f k8s/network-policies.yaml

# Verify policies applied
kubectl get networkpolicies -n euno-system
```

### Step 5: Deploy Services

```bash
# Deploy Capability Issuer
kubectl apply -f k8s/capability-issuer-deployment.yaml

# Wait for issuer to be ready
kubectl wait --for=condition=available --timeout=300s \
  deployment/capability-issuer -n euno-system

# Deploy Tool Gateway
kubectl apply -f k8s/tool-gateway-deployment.yaml

# Wait for gateway to be ready
kubectl wait --for=condition=available --timeout=300s \
  deployment/tool-gateway -n euno-system

# Verify all pods running
kubectl get pods -n euno-system
```

### Step 6: Verify Security Hardening

```bash
# Check that pods are running as non-root
kubectl get pods -n euno-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.runAsUser}{"\n"}{end}'

# Expected output:
# capability-issuer-xxx   1001
# tool-gateway-xxx        1002

# Verify AppArmor annotations
kubectl get pods -n euno-system -o json | \
  jq '.items[].metadata.annotations' | grep apparmor

# Verify resource limits
kubectl describe pods -n euno-system | grep -A 5 "Limits:"
```

### Step 7: Smoke Test

```bash
# Test health endpoints
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://capability-issuer.euno-system:3001/health

kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl http://tool-gateway.euno-system:3002/health

# Expected response: {"status":"healthy","service":"<name>"}
```

---

## Monitoring and Dashboards

### Key Metrics to Monitor

#### Capability Issuer Metrics
- **Token Issuance Rate**: tokens issued per minute
- **Token Issuance Errors**: failed issuance attempts
- **Azure Key Vault Latency**: signing operation duration
- **Azure AD Validation Latency**: token validation duration

#### Tool Gateway Metrics
- **Request Rate**: proxied requests per minute
- **Validation Latency (p95)**: token verification time (target: <5ms)
- **Denial Rate**: percentage of requests denied
- **Kill Switch Activations**: count of kill switch events

#### System Health Metrics
- **Pod Restarts**: unexpected pod restarts indicate issues
- **CPU Usage**: per-container CPU utilization
- **Memory Usage**: per-container memory utilization
- **Network Traffic**: ingress/egress bytes

### Log Aggregation

**Azure Monitor Integration:**

```bash
# Enable Container Insights on AKS
az aks enable-addons \
  --resource-group <rg-name> \
  --name <cluster-name> \
  --addons monitoring

# Query audit logs
# In Azure Monitor, use KQL:
ContainerLog
| where Namespace == "euno-system"
| where LogEntry contains '"logType":"audit"'
| project TimeGenerated, ContainerName, LogEntry
| order by TimeGenerated desc
```

**Kubectl Log Queries:**

```bash
# View all audit logs
kubectl logs -n euno-system deploy/tool-gateway | grep '"logType":"audit"'

# View denied actions
kubectl logs -n euno-system deploy/tool-gateway | grep '"decision":"deny"'

# View token issuance
kubectl logs -n euno-system deploy/capability-issuer | grep '"eventType":"issuance"'

# View kill switch events
kubectl logs -n euno-system deploy/tool-gateway | grep '"Session killed\|Agent killed"'
```

### Alert Configuration

**Recommended Alerts:**

1. **High Denial Rate**
   - Condition: >10% of requests denied in 5min window
   - Action: Notify on-call engineer

2. **Token Issuance Failures**
   - Condition: >5 issuance errors in 1min
   - Action: Page on-call engineer

3. **Kill Switch Activation**
   - Condition: Global or agent kill switch activated
   - Action: Immediate page to security team

4. **Pod Restarts**
   - Condition: Pod restart count >3 in 10min
   - Action: Investigate and notify operations

5. **High Latency**
   - Condition: p95 gateway latency >50ms
   - Action: Investigate performance issue

---

## Error Interpretation

### Common Error Codes

#### AUTHENTICATION_FAILED (401)
**Meaning:** Azure AD token validation failed or missing Authorization header

**Possible Causes:**
- Expired Azure AD token
- Invalid token format
- Misconfigured Azure AD tenant/client ID

**Troubleshooting:**
```bash
# Check issuer logs for Azure AD errors
kubectl logs -n euno-system deploy/capability-issuer | grep "AUTHENTICATION_FAILED"

# Verify Azure AD configuration
kubectl get configmap -n euno-system issuer-config -o yaml | grep -i azure

# Test token validity
curl -X POST https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token \
  -d "client_id=${CLIENT_ID}&scope=api://${CLIENT_ID}/.default&grant_type=client_credentials&client_secret=${CLIENT_SECRET}"
```

---

#### INVALID_TOKEN (401)
**Meaning:** Capability token signature verification failed

**Possible Causes:**
- Token signed with wrong key
- Token tampered with
- Public key mismatch between issuer and gateway

**Troubleshooting:**
```bash
# Verify public key consistency
kubectl exec -n euno-system deploy/capability-issuer -- \
  curl http://localhost:3001/api/v1/public-key > issuer-key.pem

kubectl exec -n euno-system deploy/tool-gateway -- \
  curl http://capability-issuer:3001/api/v1/public-key > gateway-key.pem

diff issuer-key.pem gateway-key.pem
# Should be identical
```

---

#### EXPIRED_TOKEN (401)
**Meaning:** Capability token has passed its expiration time

**Possible Causes:**
- Agent failed to renew token
- Clock skew between services
- Token TTL too short for use case

**Troubleshooting:**
```bash
# Check token expiration
echo ${TOKEN} | cut -d. -f2 | base64 -d | jq '.exp'

# Check current time on pods
kubectl exec -n euno-system deploy/tool-gateway -- date +%s

# Verify clock sync
kubectl exec -n euno-system deploy/capability-issuer -- date
kubectl exec -n euno-system deploy/tool-gateway -- date
# Should be within a few seconds
```

---

#### FORBIDDEN (403)
**Meaning:** Action denied by capability token or kill switch

**Possible Causes:**
- Insufficient capabilities for requested action
- Session/agent killed via kill switch
- Resource pattern mismatch

**Troubleshooting:**
```bash
# Check kill switch status
curl -X GET http://tool-gateway:3002/admin/kill-switch/status \
  -H "X-Admin-API-Key: ${ADMIN_API_KEY}"

# Review denial in audit logs
kubectl logs -n euno-system deploy/tool-gateway | \
  grep '"decision":"deny"' | tail -20 | jq

# Check capability scope in token
echo ${TOKEN} | cut -d. -f2 | base64 -d | jq '.cap'
```

---

#### INTERNAL_ERROR (500)
**Meaning:** Unexpected server error

**Possible Causes:**
- Azure Key Vault unavailable
- Database connection failed
- Unhandled exception in code

**Troubleshooting:**
```bash
# Check pod logs for stack traces
kubectl logs -n euno-system deploy/capability-issuer --tail=100

# Verify Azure Key Vault connectivity
kubectl exec -n euno-system deploy/capability-issuer -- \
  curl -v https://${KEYVAULT_NAME}.vault.azure.net

# Check pod resource usage
kubectl top pods -n euno-system
```

---

## Common Issues and Troubleshooting

### Issue: Pods in CrashLoopBackOff

**Symptoms:**
```bash
kubectl get pods -n euno-system
# Output shows CrashLoopBackOff
```

**Resolution:**
1. Check pod logs:
   ```bash
   kubectl logs -n euno-system <pod-name> --previous
   ```

2. Common causes:
   - Missing secrets: Verify secrets exist
   - Invalid Azure credentials: Test credentials separately
   - Port already in use: Check for port conflicts
   - Out of memory: Increase memory limits

3. Fix and redeploy:
   ```bash
   kubectl delete pod -n euno-system <pod-name>
   # Pod will be recreated by deployment
   ```

---

### Issue: Network Policy Blocking Legitimate Traffic

**Symptoms:**
- Gateway cannot reach issuer
- Agent cannot reach gateway
- Timeout errors in logs

**Resolution:**
1. Temporarily disable network policies for debugging:
   ```bash
   kubectl delete networkpolicy -n euno-system --all
   ```

2. Test connectivity:
   ```bash
   kubectl exec -n euno-system deploy/tool-gateway -- \
     curl http://capability-issuer:3001/health
   ```

3. If connectivity works, review and fix network policy rules
4. Re-apply corrected network policies

---

### Issue: High Gateway Latency

**Symptoms:**
- p95 latency >50ms
- Slow agent responses
- Timeout errors

**Resolution:**
1. Check gateway pod resources:
   ```bash
   kubectl top pods -n euno-system | grep tool-gateway
   ```

2. If CPU/memory high, scale horizontally:
   ```bash
   kubectl scale deployment tool-gateway -n euno-system --replicas=3
   ```

3. Check Azure Key Vault latency (if cryptographic audit enabled)
4. Review audit log volume (high I/O can cause latency)

---

### Issue: Token Issuance Failures

**Symptoms:**
- Agents cannot obtain tokens
- 500 errors from issuer
- "Failed to sign token" in logs

**Resolution:**
1. Verify Azure Key Vault permissions:
   ```bash
   az keyvault key show --vault-name <vault> --name capability-signing-key
   ```

2. Check managed identity has sign permission:
   ```bash
   az keyvault set-policy --name <vault> \
     --object-id <managed-identity-object-id> \
     --key-permissions sign verify
   ```

3. Test key operations:
   ```bash
   kubectl exec -n euno-system deploy/capability-issuer -- \
     curl -X POST http://localhost:3001/api/v1/issue \
       -H "Authorization: Bearer ${TEST_TOKEN}" \
       -d '{"agentId":"test-agent"}'
   ```

---

## Support Contacts

| Role | Contact | Response Time | Availability |
|------|---------|---------------|--------------|
| On-Call Engineer | oncall@example.com | 15 min | 24/7 |
| Azure Support | azure-support@example.com | 1 hour | Business hours |
| Security Team | security@example.com | 30 min | 24/7 (emergencies) |
| Product Owner | product@example.com | Next business day | Business hours |

**Escalation Path:**
1. On-Call Engineer
2. Team Lead
3. Engineering Manager
4. VP Engineering (critical incidents only)

---

## Daily Operations Checklist

### Morning Checklist

- [ ] Verify all pods are running and healthy
  ```bash
  kubectl get pods -n euno-system
  ```

- [ ] Check for pod restarts overnight
  ```bash
  kubectl get pods -n euno-system -o json | \
    jq '.items[] | {name:.metadata.name, restarts:.status.containerStatuses[].restartCount}'
  ```

- [ ] Review overnight audit logs for anomalies
  ```bash
  kubectl logs -n euno-system deploy/tool-gateway --since=12h | \
    grep '"decision":"deny"' | wc -l
  ```

- [ ] Verify no kill switches are active (unless intentional)
  ```bash
  curl http://tool-gateway:3002/admin/kill-switch/status \
    -H "X-Admin-API-Key: ${ADMIN_API_KEY}"
  ```

- [ ] Check Azure Key Vault status
  ```bash
  az keyvault show --name <vault-name> --query "properties.provisioningState"
  ```

### Weekly Checklist

- [ ] Review pilot metrics dashboard
- [ ] Analyze denial patterns for false positives
- [ ] Check for security updates to dependencies
- [ ] Rotate admin API keys (if policy requires)
- [ ] Review and archive old audit logs
- [ ] Test backup and restore procedures
- [ ] Conduct tabletop exercise of incident response

---

## Metrics and Success Criteria

### Pilot Success Metrics

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Uptime | >99.9% | - | TBD |
| Token Issuance Success Rate | >99% | - | TBD |
| Gateway Latency (p95) | <5ms | - | TBD |
| False Positive Denials | <1% | - | TBD |
| Security Incidents | 0 | - | TBD |
| Agent Satisfaction Score | >8/10 | - | TBD |

### Weekly Reporting

**Report Template:**

```
=== Euno Pilot Weekly Report ===
Week of: [Date]

METRICS:
- Tokens Issued: [count]
- Requests Validated: [count]
- Denials: [count] ([%])
- Incidents: [count]
- Uptime: [%]

TOP ISSUES:
1. [Issue description] - [Status]
2. [Issue description] - [Status]

IMPROVEMENTS NEEDED:
1. [Improvement area]
2. [Improvement area]

FEEDBACK FROM USERS:
- [Summary of user feedback]

NEXT WEEK FOCUS:
- [Priority 1]
- [Priority 2]
```

---

## Appendix: Quick Command Reference

### Get Logs
```bash
# Gateway logs
kubectl logs -n euno-system deploy/tool-gateway --tail=100 --follow

# Issuer logs
kubectl logs -n euno-system deploy/capability-issuer --tail=100 --follow

# Audit logs only
kubectl logs -n euno-system deploy/tool-gateway | grep '"logType":"audit"'
```

### Admin API Commands
```bash
# Kill switch status
curl $GATEWAY/admin/kill-switch/status -H "X-Admin-API-Key: $KEY"

# Kill session
curl -X POST $GATEWAY/admin/kill-switch/session/$SESS/kill \
  -H "X-Admin-API-Key: $KEY"

# Revoke token
curl -X POST $GATEWAY/admin/revoke \
  -H "X-Admin-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"tokenId":"$JTI"}'
```

### Debugging
```bash
# Port-forward for local testing
kubectl port-forward -n euno-system svc/capability-issuer 3001:3001
kubectl port-forward -n euno-system svc/tool-gateway 3002:3002

# Exec into pod
kubectl exec -it -n euno-system deploy/tool-gateway -- /bin/sh

# Describe pod for events
kubectl describe pod -n euno-system <pod-name>
```

---

**Document Version:** 1.0
**Last Updated:** 2026-04-27
**Next Review:** 2026-05-27
**Owner:** Operations Team
