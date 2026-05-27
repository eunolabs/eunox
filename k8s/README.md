# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the eunox capability governance system with sandboxed agent runtime.

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
  -n eunox-system

kubectl create secret generic gateway-secrets \
  --from-literal=admin-api-key=<YOUR_ADMIN_KEY> \
  -n eunox-system
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
`namespace-and-config.yaml` (`eunox-config`). Edit that file with your values:

- `keyvault-url`, `azure-tenant-id`, `azure-client-id`, `issuer-did`
- `backend-service-url`: URL of backend services

```bash
kubectl apply -f namespace-and-config.yaml
```

### 3. Deploy Services

> **Choose one manifest per component** — each component has two manifest
> variants. Applying both at the same time creates conflicting resources.
>
> | Component         | Production (recommended)                                 | Alternative (simpler, no sharding)                         |
> | ----------------- | -------------------------------------------------------- | ---------------------------------------------------------- |
> | Capability Issuer | `capability-issuer-deployment.yaml`                      | `capability-issuer.yaml` _(legacy, no Sprint 3 hardening)_ |
> | Tool Gateway      | `tool-gateway.yaml` _(StatefulSet + Envoy shard router)_ | `tool-gateway-deployment.yaml` _(plain Deployment)_        |

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
# Production: base manifest only — no broad 0.0.0.0/0 egress rules.
kubectl apply -f network-policies.yaml

# Dev / staging only: also apply the egress overlay for broad internet access
# before specific backend / Redis CIDRs are known.  DO NOT apply in production.
# kubectl apply -f network-policies-dev-overlay.yaml

# Apply HA policies (PodDisruptionBudgets + Capability Issuer HPA)
kubectl apply -f ha-policies.yaml
```

> **Admin API access:** the admin port (3003) is only reachable from pods
> labelled `role=ops`. Label your incident-response or operator pod
> before calling `/admin` endpoints:
>
> ```bash
> kubectl label pod <ops-pod> role=ops -n eunox-system
> ```

> **HA correctness:** the gateway and issuer run multiple replicas. Redis
> is required so that revocation, kill-switch propagation, per-token
> `maxCalls` counters, DPoP proof replay defense, and per-subject
> issuance rate limiting share state across pods. Without `REDIS_URL`
> each replica falls back to its own in-memory store and authorization
> decisions split-brain across the cluster. Override `redis-url` in the
> `eunox-config`, `gateway-config`, and `issuer-config` ConfigMaps to
> point at a managed Redis in production.

### 4. Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n eunox-system

# Check services
kubectl get svc -n eunox-system

# Check network policies
kubectl get networkpolicies -n eunox-system
```

## Testing Sandbox Enforcement

### Test 1: Verify Agent Can Reach Gateway

```bash
# Exec into agent pod
kubectl exec -it -n eunox-system <agent-pod-name> -- sh

# Try to reach gateway (should work)
wget -O- http://tool-gateway:3002/health
```

### Test 2: Verify External Access is Blocked (Sprint 1 Exit Criteria)

```bash
# Exec into agent pod
kubectl exec -it -n eunox-system <agent-pod-name> -- sh

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
kubectl exec -it -n eunox-system <agent-pod-name> -- sh

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
kubectl logs -n eunox-system -l app=capability-issuer --tail=50

# Check gateway logs
kubectl logs -n eunox-system -l app=tool-gateway --tail=50

# Check agent logs
kubectl logs -n eunox-system -l app=agent-runtime --tail=50
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│             Kubernetes Cluster                   │
│  ┌──────────────────────────────────────────┐   │
│  │         eunox-system namespace            │   │
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
kubectl logs -n eunox-system -l app=capability-issuer -f

# Tool Gateway logs
kubectl logs -n eunox-system -l app=tool-gateway -f

# Agent Runtime logs
kubectl logs -n eunox-system -l app=agent-runtime -f
```

### Metrics

```bash
# Pod resource usage
kubectl top pods -n eunox-system

# Network policy status
kubectl describe networkpolicy -n eunox-system
```

## Troubleshooting

### Agent Can't Reach Gateway

1. Check NetworkPolicy is applied:

   ```bash
   kubectl get networkpolicy -n eunox-system
   ```

2. Verify gateway service is running:

   ```bash
   kubectl get svc tool-gateway -n eunox-system
   ```

3. Check DNS resolution:
   ```bash
   kubectl exec -it -n eunox-system <agent-pod> -- nslookup tool-gateway
   ```

### Token Acquisition Fails

1. Check issuer is running:

   ```bash
   kubectl get pods -n eunox-system -l app=capability-issuer
   ```

2. Verify Azure credentials:

   ```bash
   kubectl get secret issuer-secrets -n eunox-system
   ```

3. Check issuer logs:
   ```bash
   kubectl logs -n eunox-system -l app=capability-issuer --tail=100
   ```

### Network Policy Not Working

1. Verify CNI supports NetworkPolicy (Calico, Cilium, etc.)
2. Check if NetworkPolicy controller is running
3. Test with a debug pod:
   ```bash
   kubectl run -it --rm debug --image=alpine -n eunox-system -- sh
   ```

## Security Considerations

1. **Secrets Management**: Use Azure Key Vault integration or sealed-secrets for production
2. **RBAC**: Apply least-privilege RBAC policies for service accounts
3. **Pod Security Standards**: Enforce restricted pod security standards
4. **Image Scanning**: Scan container images for vulnerabilities before deployment
5. **Network Policies**: Review and test network policies regularly
6. **Audit Logging**: Enable Kubernetes audit logging for compliance

## Workload placement controls (Task 7)

Both the gateway and the capability issuer carry topology spread constraints and
pod anti-affinity rules so that the replica count translates into real
failure-domain redundancy.

### What is configured

| Rule type                   | Constraint                                                                 | Effect                                                                                |
| --------------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `topologySpreadConstraints` | `topology.kubernetes.io/zone`, `maxSkew: 1`, `DoNotSchedule`               | Prevents scheduler from putting all replicas in the same availability zone            |
| `topologySpreadConstraints` | `kubernetes.io/hostname`, `maxSkew: 1`, `ScheduleAnyway`                   | Encourages spreading across nodes; `ScheduleAnyway` keeps dev/CI clusters schedulable |
| `podAntiAffinity`           | `requiredDuringSchedulingIgnoredDuringExecution`, `kubernetes.io/hostname` | Refuses to co-locate two replicas of the same workload on the same node               |

### Node count requirement

The hard `podAntiAffinity` rule on `kubernetes.io/hostname` requires the cluster
to have **at least as many schedulable nodes as replicas** for each workload:

- `capability-issuer-deployment.yaml`: 2 replicas → requires ≥ 2 nodes
- `tool-gateway-deployment.yaml`: 3 replicas → requires ≥ 3 nodes
- `tool-gateway.yaml` (StatefulSet): 3 shards → requires ≥ 3 nodes

In single-node dev / CI environments, either reduce the replica count to 1 or
change `requiredDuringSchedulingIgnoredDuringExecution` to
`preferredDuringSchedulingIgnoredDuringExecution`.

### AZ-spread requirement

The `DoNotSchedule` zone constraint ensures pods are spread across available
zones with a maximum skew of 1. It does **not** require a specific number of
AZs — a 2-AZ cluster (e.g. 2+1 distribution for 3 replicas) fully satisfies
the constraint. For single-AZ environments, change the zone constraint from
`DoNotSchedule` to `ScheduleAnyway`.

The base `network-policies.yaml` contains **no `0.0.0.0/0` or `::/0` egress
rules**. All gateway and issuer egress is scoped to in-cluster pod selectors
(DNS, Redis, Capability Issuer).

### Production egress configuration

Before deploying to production, add explicit `ipBlock` rules for each external
endpoint your cluster needs to reach. The key endpoints to configure are:

| Component                           | Endpoint type     | Recommended approach                                            |
| ----------------------------------- | ----------------- | --------------------------------------------------------------- |
| Gateway → managed Redis             | Private endpoint  | Add `ipBlock` scoped to the managed Redis private endpoint CIDR |
| Gateway → backend services          | Public or private | Add explicit backend CIDRs, or route via an egress gateway      |
| Issuer → Azure Key Vault / Azure AD | Private endpoint  | Add `ipBlock` scoped to private endpoint IPs                    |
| Issuer → managed Redis              | Private endpoint  | Add `ipBlock` scoped to the managed Redis private endpoint CIDR |

See the commented-out examples in `network-policies.yaml` for the placeholder
syntax.

### Dev / staging clusters

In environments where managed Redis and backend CIDRs are not yet known, apply
the broad-egress overlay **in addition to** the base manifest:

```bash
kubectl apply -f network-policies.yaml
kubectl apply -f network-policies-dev-overlay.yaml
```

`network-policies-dev-overlay.yaml` adds separate NetworkPolicy objects labelled
`eunox.dev/dev-only: 'true'` that allow broad internet egress from gateway and
issuer pods. This file **must not** be applied in production clusters.

### Kustomize / Helm integration

In a Kustomize setup, add `network-policies-dev-overlay.yaml` to the `resources:`
list in your dev/staging overlay directory only, not in the production base.

In Helm, use a value such as `networkPolicy.devEgressOverlay: true` to
conditionally render the overlay template per environment.

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
