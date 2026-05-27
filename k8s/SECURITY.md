# Sprint 3 Sandbox Hardening - Security Best Practices

## Overview

This document describes the Sprint 3 sandbox hardening implementation for the eunox capability governance system. All security measures are designed to prevent privilege escalation, limit resource usage, and enforce zero-trust principles at the container and Kubernetes level.

## Implemented Security Controls

### 1. Non-Privileged Users (Sprint 3 Requirement)

**Dockerfiles:**

- Capability Issuer runs as UID 1001
- Tool Gateway runs as UID 1002
- Both use dedicated non-root `eunox` user/group
- Read-only root filesystem enforced

**Implementation:**

```dockerfile
RUN addgroup -g 1001 -S eunox && \
    adduser -u 1001 -S eunox -G eunox
USER eunox
```

### 2. AppArmor Profiles (Sprint 3 Requirement)

**Profile:** `k8s/security-policies/apparmor-profile.conf`

Denies dangerous syscalls:

- `ptrace` - Prevents process tracing
- `mount/umount` - Prevents filesystem manipulation
- `sys_admin` capability - Prevents admin operations
- `sys_module` - Prevents kernel module loading
- `sys_rawio` - Prevents raw I/O access
- `setuid/setgid` - Prevents UID/GID changes
- `dac_override` - Prevents discretionary access control bypass

**Deployment:**

```bash
# Install on each Kubernetes node
sudo cp k8s/security-policies/apparmor-profile.conf /etc/apparmor.d/eunox-restricted
sudo apparmor_parser -r /etc/apparmor.d/eunox-restricted
```

Pods automatically use the profile via annotation:

```yaml
container.apparmor.security.beta.kubernetes.io/<container-name>: localhost/eunox-restricted
```

### 3. SELinux Policy (Sprint 3 Requirement)

**Policy:** `k8s/security-policies/selinux-policy.te`

Provides defense-in-depth with AppArmor. Key restrictions:

- Denies `sys_admin`, `sys_module`, `sys_rawio`, `sys_ptrace` capabilities
- Prevents ptrace, setcap, setuid, setgid operations
- Never allows kernel module operations

**Deployment:**

```bash
checkmodule -M -m -o eunox_restricted.mod k8s/security-policies/selinux-policy.te
semodule_package -o eunox_restricted.pp -m eunox_restricted.mod
semodule -i eunox_restricted.pp
```

Pods use SELinux context:

```yaml
seLinuxOptions:
  level: "s0:c123,c456"
  type: "eunox_restricted.process"
```

### 4. Resource Limits via cgroups (Sprint 3 Requirement)

**CPU Limits:**

- Capability Issuer: 250m request, 500m limit
- Tool Gateway: 500m request, 1000m limit

**Memory Limits:**

- Capability Issuer: 512Mi request, 1Gi limit
- Tool Gateway: 1Gi request, 2Gi limit

**Node.js Memory:**

```dockerfile
CMD ["node", "--max-old-space-size=512", "dist/index.js"]
```

**Namespace Quotas:**

```yaml
requests.cpu: "4"
requests.memory: 8Gi
limits.cpu: "8"
limits.memory: 16Gi
pods: "20"
```

### 5. Environment Scrubbing (Sprint 3 Requirement)

**No Sensitive Data in Environment Variables:**

Secrets via Kubernetes Secrets:

```yaml
- name: AZURE_CLIENT_SECRET
  valueFrom:
    secretKeyRef:
      name: issuer-secrets
      key: azure-client-secret
```

Configuration via ConfigMaps:

```yaml
- name: AZURE_KEYVAULT_URL
  valueFrom:
    configMapKeyRef:
      name: issuer-config
      key: keyvault-url
```

**Scrubbed from environment:**

- Client secrets
- API keys
- Admin passwords
- Service account tokens

### 6. Read-Only Root Filesystem

**Implementation:**

```yaml
securityContext:
  readOnlyRootFilesystem: true
```

**Writable Paths (tmpfs only):**

- `/tmp` - 100Mi memory limit
- `/app/.npm` - 50Mi memory limit

No persistent volumes allowed (quota: `persistentvolumeclaims: "0"`).

### 7. Network Policies

**Default Deny All:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**Capability Issuer Egress (Allowlist):**

- DNS (port 53)
- Azure Key Vault (port 443)
- Azure AD endpoints (port 443)

**Tool Gateway Egress (Allowlist):**

- DNS (port 53)
- Capability Issuer (port 3001)
- Backend services (ports 80, 443)

### 8. Pod Security Standards

**Namespace Enforcement:**

```yaml
pod-security.kubernetes.io/enforce: restricted
```

**Restricted Standard Includes:**

- `runAsNonRoot: true`
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `seccompProfile: RuntimeDefault`
- No host namespaces (`hostNetwork`, `hostPID`, `hostIPC`: `false`)

### 9. Additional Security Controls

**Container Capabilities:**

```yaml
capabilities:
  drop:
    - ALL
```

**Seccomp Profile:**

```yaml
seccompProfile:
  type: RuntimeDefault
```

**Service Account Token:**

- Minimal RBAC permissions
- Can only read specific ConfigMaps/Secrets

**Health Checks:**

- Liveness probe every 30s
- Readiness probe every 10s
- Automatic pod restart on failure

## Deployment Checklist

### Prerequisites

1. **Kubernetes Cluster Setup:**

   ```bash
   # Enable Pod Security Admission
   kubectl label namespace eunox-system pod-security.kubernetes.io/enforce=restricted

   # Create namespace
   kubectl apply -f k8s/pod-security-standards.yaml
   ```

2. **Install AppArmor (on each node):**

   ```bash
   sudo apt-get install apparmor-utils
   sudo cp k8s/security-policies/apparmor-profile.conf /etc/apparmor.d/eunox-restricted
   sudo apparmor_parser -r /etc/apparmor.d/eunox-restricted
   sudo systemctl restart apparmor
   ```

3. **Install SELinux (RHEL/CentOS nodes):**

   ```bash
   sudo yum install selinux-policy-devel
   cd k8s/security-policies
   make -f /usr/share/selinux/devel/Makefile
   sudo semodule -i eunox_restricted.pp
   ```

4. **Create Secrets:**

   ```bash
   kubectl create secret generic issuer-secrets \
     --from-literal=azure-client-secret="YOUR_SECRET" \
     --namespace=eunox-system

   kubectl create secret generic gateway-secrets \
     --from-literal=admin-api-key="YOUR_API_KEY" \
     --namespace=eunox-system
   ```

5. **Update ConfigMaps:**

   ```bash
   # Edit k8s/capability-issuer-deployment.yaml
   # Update issuer-config ConfigMap with your values

   # Edit k8s/tool-gateway-deployment.yaml
   # Update gateway-config ConfigMap with your values
   ```

### Deployment

```bash
# Apply network policies
kubectl apply -f k8s/network-policies.yaml

# Deploy capability issuer
kubectl apply -f k8s/capability-issuer-deployment.yaml

# Deploy tool gateway
kubectl apply -f k8s/tool-gateway-deployment.yaml

# Verify security contexts
kubectl get pods -n eunox-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.runAsUser}{"\n"}{end}'
```

### Verification

```bash
# Check AppArmor enforcement
kubectl exec -n eunox-system <pod-name> -- cat /proc/self/attr/current

# Check resource limits
kubectl describe pod -n eunox-system <pod-name> | grep -A 10 "Limits"

# Check network policies
kubectl get networkpolicies -n eunox-system

# Test forbidden operations (should fail)
kubectl exec -n eunox-system <pod-name> -- mount /dev/sda1 /mnt  # Should fail
kubectl exec -n eunox-system <pod-name> -- su -  # Should fail
```

## Security Validation

### Sprint 3 Exit Criteria Compliance

✅ **Process runs as non-privileged OS user**

- UIDs 1001/1002, non-root enforced

✅ **AppArmor/SELinux profiles prevent dangerous syscalls**

- ptrace, mount, sys_admin, sys_module blocked

✅ **CPU and memory limits via cgroups**

- 250m-1000m CPU, 512Mi-2Gi memory per container

✅ **Environment scrubbing**

- No secrets in environment variables
- Kubernetes Secrets for sensitive data

✅ **Read-only root filesystem**

- Only tmpfs mounts are writable

✅ **Network egress restrictions**

- Default deny with allowlist-only egress

## Troubleshooting

### AppArmor Issues

```bash
# Check AppArmor status
sudo aa-status | grep eunox

# View denials
sudo journalctl -xe | grep apparmor | grep DENIED

# Reload profile
sudo apparmor_parser -r /etc/apparmor.d/eunox-restricted
```

### SELinux Issues

```bash
# Check SELinux mode
getenforce

# View denials
sudo ausearch -m avc -ts recent | grep eunox

# Reload policy
sudo semodule -r eunox_restricted
sudo semodule -i eunox_restricted.pp
```

### Resource Limit Issues

```bash
# Check pod resource usage
kubectl top pods -n eunox-system

# Check if pods are throttled
kubectl describe pod -n eunox-system <pod-name> | grep -i throttl

# View resource quota usage
kubectl describe resourcequota -n eunox-system
```

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [AppArmor in Kubernetes](https://kubernetes.io/docs/tutorials/security/apparmor/)
- [SELinux for Containers](https://www.redhat.com/en/blog/selinux-containers)
- [Resource Management in Kubernetes](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
