# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the Euno capability governance system with sandboxed agent runtime.

## Sprint 1 & Sprint 2 Sandboxing Implementation

### Security Features Implemented

#### Sprint 1: Agent Environment & Sandbox

1. **Network Isolation** (`network-policies.yaml`)
   - Agents can ONLY communicate with Tool Gateway and Capability Issuer
   - All other egress traffic is blocked
   - Implements the principle: "the model is not your boundary"
   - Exit criteria: `curl` to unauthorized URL from agent container is blocked

2. **Container Security** (`agent-runtime.yaml`)
   - Read-only root filesystem
   - Runs as non-root user (UID 1000)
   - All Linux capabilities dropped
   - No sensitive host paths mounted
   - Only ephemeral volumes for scratch space

3. **Resource Constraints**
   - CPU and memory limits enforced
   - Prevents resource exhaustion attacks

#### Sprint 2: Sandbox Refinement

1. **Network Proxy** (`runtime.ts`)
   - HTTP/HTTPS requests made via `AgentRuntime` methods are routed through the gateway
   - Gateway validates capability tokens for gateway-routed requests
   - Direct external egress is blocked by Kubernetes network policies; `runtime.ts` does not transparently intercept arbitrary in-process HTTP clients

2. **Token Management**
   - Automatic token acquisition on startup
   - Token refresh every 10 minutes (configurable)
   - Automatic retry on 401 (expired token)

## Prerequisites

- Kubernetes cluster (v1.24+)
- Azure Container Registry (ACR) access
- Azure Key Vault configured
- Azure AD application registered

## Quick Start

### 1. Create Namespace and Secrets

```bash
# Create namespace
kubectl apply -f namespace-and-config.yaml

# Create secrets
kubectl create secret generic issuer-secrets \
  --from-literal=azure-client-secret=<YOUR_SECRET> \
  -n euno-system

kubectl create secret generic gateway-secrets \
  --from-literal=admin-api-key=<YOUR_ADMIN_KEY> \
  -n euno-system
```

### 2. Update ConfigMap

The **Capability Issuer** (Sprint 3 hardened variant) reads its configuration
from the `issuer-config` ConfigMap that is **embedded at the bottom of
`capability-issuer-deployment.yaml`** — not from `namespace-and-config.yaml`.
Update the values there before applying:
- `keyvault-url`: Your Azure Key Vault URL
- `tenant-id`: Your Azure AD tenant ID
- `client-id`: Your Azure AD application ID
- `issuer-did`: Your DID (e.g., `did:web:yourdomain.com`)

The **Tool Gateway** and agent runtime read their shared settings from
`namespace-and-config.yaml` (`euno-config`).  Edit that file with your values:
- `keyvault-url`, `azure-tenant-id`, `azure-client-id`, `issuer-did`
- `backend-service-url`: URL of backend services

```bash
kubectl apply -f namespace-and-config.yaml
```

### 3. Deploy Services

> **Choose one manifest per component** — each component has two manifest
> variants.  Applying both at the same time creates conflicting resources.
>
> | Component | Production (recommended) | Alternative (simpler, no sharding) |
> |---|---|---|
> | Capability Issuer | `capability-issuer-deployment.yaml` | `capability-issuer.yaml` *(legacy, no Sprint 3 hardening)* |
> | Tool Gateway | `tool-gateway.yaml` *(StatefulSet + Envoy shard router)* | `tool-gateway-deployment.yaml` *(plain Deployment)* |

```bash
# Deploy Redis (distributed coordination backend — REQUIRED for HA)
# Skip this step if you point `redis-url` at a managed Redis instance
# (Azure Cache for Redis, ElastiCache, Memorystore) in the ConfigMaps.
kubectl apply -f redis.yaml

# Apply pod security standards (namespace-wide baseline/restricted policy)
kubectl apply -f pod-security-standards.yaml

# Deploy Capability Issuer (hardened Sprint 3 variant)
kubectl apply -f capability-issuer-deployment.yaml

# Deploy Tool Gateway (StatefulSet + Envoy shard router)
kubectl apply -f tool-gateway.yaml
kubectl apply -f envoy-shard-router.yaml

# Deploy Agent Runtime
# agent-runtime.yaml points GATEWAY_URL at envoy-shard-router:3002 so every
# agent's requests are consistently hashed to the correct gateway shard (H-1).
# Sharding is a performance optimization — security enforcement lives in the
# gateway regardless of routing.  If you need to bypass the Envoy router
# (e.g. for debugging), update GATEWAY_URL to http://tool-gateway:3002;
# the gateway will fall back to Redis for call-counter operations.
kubectl apply -f agent-runtime.yaml

# Apply Network Policies (Sprint 1 requirement)
kubectl apply -f network-policies.yaml

# Apply HA policies (PodDisruptionBudgets + Capability Issuer HPA)
kubectl apply -f ha-policies.yaml
```

> **Admin API access:** the admin port (3003) is only reachable from pods
> labelled `role=ops`.  Label your incident-response or operator pod
> before calling `/admin` endpoints:
> ```bash
> kubectl label pod <ops-pod> role=ops -n euno-system
> ```

> **HA correctness:** the gateway and issuer run multiple replicas. Redis
> is required so that revocation, kill-switch propagation, per-token
> `maxCalls` counters, DPoP proof replay defense, and per-subject
> issuance rate limiting share state across pods. Without `REDIS_URL`
> each replica falls back to its own in-memory store and authorization
> decisions split-brain across the cluster. Override `redis-url` in the
> `euno-config`, `gateway-config`, and `issuer-config` ConfigMaps to
> point at a managed Redis in production.

### 4. Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n euno-system

# Check services
kubectl get svc -n euno-system

# Check network policies
kubectl get networkpolicies -n euno-system
```

## Testing Sandbox Enforcement

### Test 1: Verify Agent Can Reach Gateway

```bash
# Exec into agent pod
kubectl exec -it -n euno-system <agent-pod-name> -- sh

# Try to reach gateway (should work)
wget -O- http://tool-gateway:3002/health
```

### Test 2: Verify External Access is Blocked (Sprint 1 Exit Criteria)

```bash
# Exec into agent pod
kubectl exec -it -n euno-system <agent-pod-name> -- sh

# Try to reach external URL (should FAIL - this is expected!)
curl http://example.com
# Expected: Connection timeout or "could not resolve host"

# Try to reach arbitrary internal service (should FAIL)
curl http://kubernetes.default.svc.cluster.local
# Expected: Connection timeout
```

### Test 3: Verify Read-Only Filesystem

```bash
# Exec into agent pod
kubectl exec -it -n euno-system <agent-pod-name> -- sh

# Try to write to root filesystem (should FAIL)
touch /test.txt
# Expected: "Read-only file system"

# Writing to /tmp should work (mounted volume)
touch /tmp/test.txt
# Expected: Success
```

### Test 4: Verify Capability Token Flow

```bash
# Check issuer logs
kubectl logs -n euno-system -l app=capability-issuer --tail=50

# Check gateway logs
kubectl logs -n euno-system -l app=tool-gateway --tail=50

# Check agent logs
kubectl logs -n euno-system -l app=agent-runtime --tail=50
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│             Kubernetes Cluster                   │
│  ┌──────────────────────────────────────────┐   │
│  │         euno-system namespace            │   │
│  │                                          │   │
│  │  ┌──────────────┐                       │   │
│  │  │    Agent     │ (NetworkPolicy)       │   │
│  │  │   Runtime    │ - Only egress to      │   │
│  │  │              │   Gateway & Issuer    │   │
│  │  │  - Read-only │ - No other network    │   │
│  │  │    rootfs    │   access allowed      │   │
│  │  │  - No caps   │                       │   │
│  │  └──────┬───────┘                       │   │
│  │         │ Capability Token               │   │
│  │         ▼                                 │   │
│  │  ┌──────────────┐    ┌────────────────┐ │   │
│  │  │     Tool     │    │   Capability   │ │   │
│  │  │   Gateway    │◄───│    Issuer      │ │   │
│  │  │              │    │                │ │   │
│  │  │ - Validates  │    │ - Azure AD     │ │   │
│  │  │   tokens     │    │ - Key Vault    │ │   │
│  │  │ - Enforces   │    │ - Signs tokens │ │   │
│  │  │   policy     │    │                │ │   │
│  │  └──────┬───────┘    └────────────────┘ │   │
│  │         │                                 │   │
│  └─────────┼─────────────────────────────────┘   │
│            │ (Allowed egress)                    │
│            ▼                                     │
│      Backend Services                            │
└─────────────────────────────────────────────────┘
```

## Monitoring

### View Logs

```bash
# Capability Issuer logs
kubectl logs -n euno-system -l app=capability-issuer -f

# Tool Gateway logs
kubectl logs -n euno-system -l app=tool-gateway -f

# Agent Runtime logs
kubectl logs -n euno-system -l app=agent-runtime -f
```

### Metrics

```bash
# Pod resource usage
kubectl top pods -n euno-system

# Network policy status
kubectl describe networkpolicy -n euno-system
```

## Troubleshooting

### Agent Can't Reach Gateway

1. Check NetworkPolicy is applied:
   ```bash
   kubectl get networkpolicy -n euno-system
   ```

2. Verify gateway service is running:
   ```bash
   kubectl get svc tool-gateway -n euno-system
   ```

3. Check DNS resolution:
   ```bash
   kubectl exec -it -n euno-system <agent-pod> -- nslookup tool-gateway
   ```

### Token Acquisition Fails

1. Check issuer is running:
   ```bash
   kubectl get pods -n euno-system -l app=capability-issuer
   ```

2. Verify Azure credentials:
   ```bash
   kubectl get secret issuer-secrets -n euno-system
   ```

3. Check issuer logs:
   ```bash
   kubectl logs -n euno-system -l app=capability-issuer --tail=100
   ```

### Network Policy Not Working

1. Verify CNI supports NetworkPolicy (Calico, Cilium, etc.)
2. Check if NetworkPolicy controller is running
3. Test with a debug pod:
   ```bash
   kubectl run -it --rm debug --image=alpine -n euno-system -- sh
   ```

## Security Considerations

1. **Secrets Management**: Use Azure Key Vault integration or sealed-secrets for production
2. **RBAC**: Apply least-privilege RBAC policies for service accounts
3. **Pod Security Standards**: Enforce restricted pod security standards
4. **Image Scanning**: Scan container images for vulnerabilities before deployment
5. **Network Policies**: Review and test network policies regularly
6. **Audit Logging**: Enable Kubernetes audit logging for compliance

## Sprint 1 Exit Criteria Verification

✅ Agent container can call test endpoint through Gateway
✅ Agent fails to reach disallowed endpoints
✅ Running `curl` to unauthorized URL from container is blocked
✅ Read-only root filesystem enforced
✅ Least-privilege Linux capabilities (all dropped)
✅ No sensitive host paths accessible
✅ Only ephemeral volumes mounted

## Sprint 2 Exit Criteria Verification

✅ All external communications funnel through Gateway
✅ HTTP/HTTPS requests via AgentRuntime routed through gateway; NetworkPolicy enforces no direct egress
✅ Token refresh implemented
✅ No direct network egress except through gateway

## Next Steps

- Implement Azure Workload Identity for pod authentication
- Add horizontal pod autoscaling
- Configure Azure Monitor integration
- Set up alerting for denied actions
- Implement kill-switch functionality (Sprint 2)
