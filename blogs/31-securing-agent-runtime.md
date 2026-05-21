# Locking Down the Agent Runtime: A Field Guide to Sandboxing Every Tool Call

*This post builds on the architecture established in [post 14 (AGT: defense in depth inside the agent process)](./14-agt-defense-in-depth.md) and the enforcement pipeline described in [post 10 (The Tool Gateway as a reference monitor)](../../blogs/10-tool-gateway-reference-monitor.md). If you haven't read those, the short version: every tool call an agent makes passes through a policy decision point — the Tool Gateway — that enforces capability tokens, conditions, and audit obligations before forwarding to the backend. This post is about the outer shell of that architecture: the OS and VM layer that makes bypassing the gateway physically impossible, not just policy-prohibited. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

I want to start with an honest admission: for the first several months of building euno, I was thinking about security at the wrong layer.

I was focused on the gateway — making the enforcement logic correct, making the audit log tamper-evident, making conditions evaluate correctly. That work matters. But I was mentally modeling the agent as a cooperative participant. I was thinking: the agent will use our SDK, it will route tool calls through the gateway, and the gateway will enforce policy.

What I wasn't sufficiently worried about was the scenario where the agent *doesn't* use our SDK. Or where a prompt injection attack coerces the agent into spawning a subprocess, opening a raw socket, or writing credentials to disk. Or where a compromised npm package in the agent's dependency tree exfiltrates data through a DNS side-channel before the gateway ever sees a tool call.

The gateway is necessary. It is not sufficient. The environment the agent process runs in has to make those escapes structurally impossible — not just policy-prohibited, not just logged, but *impossible at the kernel or hypervisor level*. That's what this post is about.

---

## The threat model that changes everything

Most agent security thinking assumes a cooperative agent. The agent is your code. It's running your SDK. It calls `invokeTool()` through the guard and the gateway like it's supposed to. The threat model is: what if the *model output* is adversarial? What if the LLM, having been prompt-injected, generates arguments that try to exploit the tool backend?

That's a real threat. [Post 18 covers SQL injection through an LLM in detail.](./18-defense-in-depth-sql-injection.md) But there's a harder threat model: **what if the agent process itself becomes adversarial?**

A supply chain compromise in a popular Python or Node package can turn your agent's process into an attacker-controlled process. A jailbroken model with tool-use capability can attempt to spawn subprocesses, read `/proc`, or make raw network calls. A sufficiently sophisticated prompt injection can convince a code-execution agent to run arbitrary system commands. In any of these scenarios, the agent process is no longer cooperating with your SDK. It's actively trying to escape.

When the agent process is adversarial, the gateway is not enough. An adversarial agent process can:
- Make direct TCP connections to backends, bypassing the gateway entirely
- Read credentials from environment variables or mounted secrets
- Exfiltrate data through DNS lookups, which often bypass HTTP-level controls
- Write to persistent storage that outlives the agent session
- Use the network identity of its container to impersonate other services

None of these are stopped by JWT validation at the gateway. They're stopped by OS-level controls: network namespaces, syscall filtering, kernel isolation.

---

## The three-layer model (and why the outer layer gets underinvested)

The architecture I've landed on, after working through the threat models and the implementation realities across multiple deployment environments, is a three-layer stack:

**Outer layer: OS/VM isolation.** The agent process runs in a contained environment — container namespaces, seccomp profiles, microVM boundaries — that structurally prevents access to anything outside the allowed surface. Network egress is blocked at the kernel or hypervisor level except to the gateway. Filesystem access is read-only except for specific tmpfs mounts. Syscalls outside an allowlist are blocked.

**Middle layer: the gateway reference monitor.** Every outbound operation goes through the gateway. The gateway verifies capability tokens, evaluates conditions, applies obligations, and writes tamper-evident audit records. [Post 10 covers this in detail.](../../blogs/10-tool-gateway-reference-monitor.md)

**Inner layer: in-process policy checking.** The AGT guard runs inside the agent process, pre-screening tool calls against the capability manifest before they hit the network. [Post 14 covers this.](./14-agt-defense-in-depth.md) This layer is soft — it can be bypassed by a sufficiently adversarial agent — which is why it's the *inner* layer, not the outer one.

The security industry has spent 30 years figuring out how to make the outer layer right for traditional workloads. For AI agents, we're applying those lessons to a new kind of workload — one that generates behavior dynamically, can be influenced by its inputs, and may use general-purpose tool-execution capabilities that look a lot like shell access. The principles are the same; the parameterization is different.

Where I see teams underinvest: they implement the middle layer (the gateway) and the inner layer (the guard), and they treat the outer layer as "we'll containerize it." Containerization is necessary but not sufficient. A container is not a sandbox. Let me explain what I mean by that.

---

## Why a plain container is not a sandbox

When you run a Docker container without modification, you're getting:

- Process isolation via Linux namespaces (PID, mount, network, IPC)
- Resource limits via cgroups
- A separate filesystem via an overlay filesystem

What you're *not* getting:

- Syscall filtering (the container process can invoke any syscall the kernel supports)
- Write protection against kernel exploits (the container shares the host kernel)
- Protection against container escape via kernel vulnerabilities

The Linux kernel has a CVE surface. Every year there are kernel privilege escalation vulnerabilities. In a default container setup, an agent process that exploits a kernel vulnerability can break out to the host. In 2019, runc — the container runtime used by Docker and Kubernetes — had a critical container escape vulnerability (CVE-2019-5736) that allowed a malicious container to overwrite the host's runc binary. The container model's security guarantee depends on the host kernel being uncompromised.

For most workloads, this is an acceptable risk. For AI agents that process untrusted inputs and may be running LLM-generated code, it's not. The threat model includes the possibility that the agent is actively trying to exploit its environment.

This is the gap that seccomp, gVisor, and microVMs are designed to close.

---

## Seccomp: syscall filtering without a new kernel

Seccomp (Secure Computing mode) is a Linux kernel feature that lets you restrict which system calls a process can make. A seccomp filter is a BPF program that runs on every syscall, deciding whether to allow, deny, or terminate the calling process.

This is your first line of defense and the lowest-overhead option. A well-crafted seccomp profile for an AI agent runtime can reduce the available syscall surface from ~400+ calls to maybe 50-80 that the agent actually needs.

The key insight for an agent workload is what you can remove. A Node.js or Python agent running ML inference and making HTTP calls to the gateway needs:

- Network calls: `socket`, `connect`, `send`, `recv`, `poll`
- File I/O for allowed paths: `read`, `write`, `open`, `close`, `stat`
- Process management: `futex`, `clone` (for threads), `exit`, `wait4`
- Memory: `mmap`, `mprotect`, `brk`

What it absolutely does not need:

- `ptrace` — lets a process trace and control another process
- `process_vm_readv` / `process_vm_writev` — read/write another process's memory
- `perf_event_open` — hardware performance counters (used in side-channel attacks)
- `mount` — mount filesystems
- `kexec_load` — load a new kernel
- `open_by_handle_at` — used in some container escape techniques
- `setns` — join another process's namespaces

The Docker default seccomp profile blocks about 44 syscalls. That's a reasonable starting point. For an agent runtime where you've enumerated the actual requirements, you can go further — blocking `ptrace`, `process_vm_readv`, and `perf_event_open` specifically closes several known lateral-movement and side-channel attack vectors.

Here's an illustrative starting point (not a minimal profile) for what a restricted seccomp profile can look like in practice:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": [
        "read", "write", "close", "fstat", "mmap", "mprotect",
        "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "ioctl", "access", "pipe", "select",
        "sched_yield", "mremap", "msync", "madvise", "shmget",
        "shmat", "shmctl", "dup", "dup2", "nanosleep", "getitimer",
        "alarm", "setitimer", "getpid", "socket", "connect",
        "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "shutdown", "bind", "listen", "getsockname", "getpeername",
        "socketpair", "setsockopt", "getsockopt", "clone", "fork",
        "vfork", "execve", "exit", "wait4", "kill", "uname",
        "fcntl", "flock", "fsync", "fdatasync", "truncate",
        "ftruncate", "getcwd", "chdir", "rename", "mkdir", "rmdir",
        "unlink", "symlink", "readlink", "chmod", "fchmod",
        "chown", "fchown", "lchown", "umask", "gettimeofday",
        "getrlimit", "getrusage", "sysinfo", "times", "getuid",
        "syslog", "getgid", "getppid", "getpgrp", "geteuid",
        "getegid", "getgroups", "setgroups", "getresuid",
        "getresgid", "getpgid", "getsid", "capget", "capset",
        "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
        "rt_sigsuspend", "sigaltstack", "utime", "mknod",
        "uselib", "personality", "ustat", "statfs", "fstatfs",
        "sysfs", "getpriority", "setpriority", "sched_setparam",
        "sched_getparam", "sched_setscheduler", "sched_getscheduler",
        "sched_get_priority_max", "sched_get_priority_min",
        "sched_rr_get_interval", "mlock", "munlock", "mlockall",
        "munlockall", "vhangup", "pivot_root", "prctl",
        "arch_prctl", "setrlimit", "sync", "acct", "settimeofday",
        "quotactl", "gettid", "readahead", "setxattr", "lsetxattr",
        "fsetxattr", "getxattr", "lgetxattr", "fgetxattr",
        "listxattr", "llistxattr", "flistxattr", "removexattr",
        "lremovexattr", "fremovexattr", "tkill", "futex",
        "sched_setaffinity", "sched_getaffinity", "io_setup",
        "io_destroy", "io_getevents", "io_submit", "io_cancel",
        "exit_group", "epoll_create", "epoll_ctl", "epoll_wait",
        "set_tid_address", "restart_syscall", "semtimedop",
        "fadvise64", "timer_create", "timer_settime", "timer_gettime",
        "timer_getoverrun", "timer_delete", "clock_settime",
        "clock_gettime", "clock_getres", "clock_nanosleep",
        "tgkill", "mbind", "set_mempolicy", "get_mempolicy",
        "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive",
        "mq_notify", "mq_getsetattr", "waitid", "inotify_init",
        "inotify_add_watch", "inotify_rm_watch", "openat",
        "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat",
        "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat",
        "fchmodat", "faccessat", "pselect6", "ppoll",
        "set_robust_list", "get_robust_list", "splice", "tee",
        "sync_file_range", "vmsplice", "move_pages",
        "utimensat", "epoll_pwait", "signalfd", "timerfd_create",
        "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
        "accept4", "signalfd4", "eventfd2", "epoll_create1",
        "dup3", "pipe2", "inotify_init1", "preadv", "pwritev",
        "rt_tgsigqueueinfo", "recvmmsg",
        "prlimit64", "fanotify_init", "fanotify_mark",
        "name_to_handle_at", "clock_adjtime",
        "syncfs", "sendmmsg", "getcpu",
        "kcmp", "finit_module", "sched_setattr", "sched_getattr",
        "renameat2", "seccomp", "getrandom", "memfd_create",
        "bpf", "execveat", "userfaultfd",
        "membarrier", "mlock2", "copy_file_range", "preadv2",
        "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free",
        "statx", "io_pgetevents", "rseq"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

That's a whitelist approach — everything not explicitly listed is denied with EPERM. The key omissions from this list: `ptrace` and `process_vm_readv` / `process_vm_writev` (cross-process inspection, used in lateral movement and memory-scraping attacks), `perf_event_open` (hardware performance counters, used in side-channel attacks like Spectre), `kexec_load` and `kexec_file_load` (kernel reload — no agent should ever need these), `open_by_handle_at` (involved in several container escape techniques), `setns` (join another namespace — useful for escaping container isolation), and `mount` (filesystem manipulation). For most agent workloads, this starter list should be tightened further by removing process-spawning and powerful kernel primitives such as `fork`, `vfork`, `execve`, and `bpf` unless you have a documented need for them. You'd tune this further for your specific runtime: a Node.js agent has different syscall requirements than a Python agent.

The overhead of seccomp filtering is low — typically less than 1% in benchmarks that stress system call rate. For an agent that's spending most of its time doing inference or waiting on network I/O, seccomp has essentially zero performance impact.

One practical note: don't write seccomp profiles by hand for production. Use a tool like `seccomp-tools` or `sysdig` to trace a representative agent session under load and automatically generate the minimum required set. Hand-crafted profiles tend to miss edge cases (a library that calls an unexpected syscall on an unusual code path) and end up either too permissive or causing mysterious crashes in production.

---

## eBPF: runtime visibility and enforcement

Seccomp filters are compiled-in at process start and are static. eBPF (extended Berkeley Packet Filter) is different: it's a kernel-level JIT runtime that lets you attach programs to kernel events dynamically, at runtime, without modifying the kernel or restarting the workload.

For agent sandboxing, eBPF is useful in two complementary ways: observability and enforcement.

### eBPF for observability

The classic problem with agent workloads is that you can enforce a seccomp profile at container start, but you have no visibility into what the agent process is *attempting* to do. Did it try to call `ptrace` and get an EPERM? Did it open a network socket to an IP address you didn't expect? Did it try to exec a subprocess?

eBPF gives you that visibility without the overhead of audit frameworks like auditd (which can be surprisingly expensive at high event rates). A Falco rule or a Tetragon policy attached via eBPF can:

- Alert on any `execve` syscall from the agent process (a process spawning subprocesses is anomalous for an agent)
- Alert on outbound TCP connections to anything other than the gateway's IP range
- Alert on file opens outside the allowed mount paths
- Alert on attempts to call blocked syscalls (even when they're denied by seccomp)

The last one is particularly useful for threat hunting: seccomp will deny the call silently (returning EPERM), but eBPF can observe that the denied call was attempted. This distinction matters — a seccomp deny that fires repeatedly is a signal that something is actively probing your restrictions.

### eBPF for enforcement

Cilium and Tetragon take eBPF beyond observability into actual enforcement: network policy enforcement at the kernel level via eBPF-based packet filtering, and process-level security policies via Tetragon's `TracingPolicy` CRD.

A Tetragon `TracingPolicy` that enforces network egress for the agent:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: agent-network-egress
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - 1          # agent process PID (known at pod startup)
      matchNamespaces:
      - namespace: Net
        operator: In
        values:
        - "agent-namespace"
      matchActions:
      - action: Sigkill
        argError: -EPERM
```

This kills the agent process on any `tcp_connect` that doesn't match allowed selectors — an enforcement action that happens *before* the packet even reaches the network stack, at the kernel level. Combining this with Cilium network policies (which enforce at the pod level) gives you layered network enforcement: Cilium blocks at the pod network level, Tetragon blocks at the process syscall level.

The operational tradeoff: eBPF-based enforcement adds kernel version and architecture dependencies. You need kernel 5.4+ for the eBPF features used by Cilium/Tetragon, and some of the newer Tetragon features (like full LSM hook coverage) require 5.15+. On managed Kubernetes, this is usually fine — EKS, GKE, and AKS are all on kernels that support what you need. On-prem with older kernels can be a constraint.

---

## gVisor: kernel isolation without a full hypervisor

gVisor is Google's container sandbox: a user-space kernel that intercepts system calls from container processes and implements them in Go, without passing them to the host kernel. The container process thinks it's talking to a Linux kernel; it's actually talking to gVisor's kernel emulation layer (called `runsc`).

The security property this provides: even if the container process exploits a vulnerability in the Linux kernel, it's exploiting gVisor's implementation of that kernel, not the host kernel. Escaping the container now requires exploiting both gVisor's user-space kernel *and* the host kernel. That's a substantially higher bar.

The operational tradeoffs are real:
- **Performance**: System calls have higher overhead through gVisor because they're intercepted and emulated in user space. For I/O-bound workloads like network-heavy agents, this can add 10-30% latency on syscall-intensive paths. Inference itself (which doesn't involve syscalls) is unaffected.
- **Compatibility**: Some syscalls, kernel features, or `/proc` entries that applications rely on aren't fully emulated in gVisor. Particularly: any use of raw sockets, some ioctls, and kernel module loading won't work. For most agent workloads (Node.js, Python, running inference via a model server), gVisor compatibility is fine.
- **eBPF limitations**: gVisor intercepts syscalls before they reach the host kernel, which means eBPF probes on the host kernel don't see the agent's syscalls. You can't use Tetragon's kprobes to observe gVisor-sandboxed containers. If you want process-level observability on gVisor workloads, you need gVisor's own tracing mechanisms.

In Kubernetes, gVisor runs through the `runsc` RuntimeClass. Enabling it for an agent pod is a one-line change:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent-session
spec:
  runtimeClassName: gvisor
  containers:
  - name: agent
    image: your-registry/agent:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```

GKE's Sandbox (which is gVisor-based) is available as a node pool configuration. AKS offers pod sandboxing via Kata Containers (described below). EKS requires deploying gVisor manually.

The right question for gVisor adoption isn't "is it perfectly compatible?" It's "what's the threat model and what's the performance budget?" For agent workloads where you're worried about prompt injection enabling kernel-level exploits, the compatibility tradeoffs are usually acceptable and the threat reduction is substantial.

---

## Kata Containers and microVMs: full hypervisor isolation

Kata Containers takes the isolation further than gVisor: each container (or pod) runs in a lightweight virtual machine with a separate kernel. The container workload doesn't share the host kernel at all. A kernel exploit inside a Kata Container is contained within the VM's kernel; it cannot affect the host.

The VM overhead is lower than you might expect. Kata Containers uses QEMU/KVM (or Firecracker, or Cloud Hypervisor — the runtime is pluggable) with a stripped-down guest kernel. Cold-start latency is typically 1-3 seconds for a new VM, which is higher than a plain container but acceptable for session-scoped agent workloads.

**Firecracker** is worth calling out specifically. It's the microVM technology that powers AWS Lambda and AWS Fargate — AWS's production bet on microVM-per-workload isolation. Firecracker VMs boot in ~125ms, use a minimal device model (virtio-net, virtio-block, vsock), and have a TCB of roughly 50,000 lines of Rust (compared to ~28 million lines for QEMU). The attack surface is dramatically smaller.

For standalone non-Kubernetes deployments, Firecracker is probably the best isolation technology available today for high-assurance agent workloads. The operational model:

1. A hypervisor host (bare-metal or cloud VM with KVM access) runs the Firecracker VMM process per agent session
2. Each microVM gets a minimal rootfs (Alpine or a custom minimal image), the agent code, and network access to only the gateway
3. The VM is destroyed after the session; any state the agent needs to persist goes through the gateway's tool calls to controlled backends

In Kubernetes, Kata Containers is the bridge between the Kubernetes scheduling model and microVM isolation. AKS's pod sandboxing uses Kata Containers with QEMU-based isolation. You get the Kubernetes API (deployments, services, RBAC, resource limits) while running the workload in a separate kernel.

```yaml
# AKS pod sandboxing — Kata Containers via RuntimeClass
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-mshv-vm-isolation
handler: kata-mshv-vm-isolation
---
apiVersion: v1
kind: Pod
metadata:
  name: agent-session
  namespace: agent-workloads
spec:
  runtimeClassName: kata-mshv-vm-isolation
  containers:
  - name: agent
    image: your-registry/agent:latest
    resources:
      limits:
        memory: "2Gi"
        cpu: "2"
    env:
    - name: EUNO_GATEWAY_URL
      value: "https://gateway.internal:8080"
    - name: EUNO_AGENT_TOKEN
      valueFrom:
        secretKeyRef:
          name: agent-token
          key: token
```

The mutual exclusion problem on GKE that the `sandboxing.md` doc references is real and worth understanding: on GKE, enabling GKE Sandbox (gVisor) on a node pool disables the ability to use eBPF-based network policies via Dataplane V2 (Cilium) on that same node pool. You have to choose between gVisor's syscall isolation and Cilium's eBPF-based network enforcement. The right answer for high-assurance workloads is to run agent pods on dedicated node pools with gVisor or Kata, and rely on VPC-level firewall rules (rather than Cilium network policies) for network enforcement on those nodes.

---

## Network locking: making the gateway the only reachable destination

All of the above is runtime isolation — preventing the agent process from doing dangerous things at the kernel level. Network locking is the complement: ensuring that even if the agent process somehow gets unrestricted network access (say, through a configuration mistake or a sandbox escape), there's nowhere useful for it to connect to.

The approach varies by environment:

### Kubernetes (non-gVisor)

Kubernetes `NetworkPolicy` (enforced by Cilium in clusters that use Cilium) with a default-deny ingress/egress posture:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-workloads-deny-all
  namespace: agent-workloads
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-allow-gateway-egress
  namespace: agent-workloads
spec:
  podSelector:
    matchLabels:
      role: agent
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: gateway
      podSelector:
        matchLabels:
          app: tool-gateway
    ports:
    - protocol: TCP
      port: 8080
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53    # DNS, scoped to cluster DNS only
```

This allows agent pods to reach the gateway and the cluster DNS resolver (for gateway hostname resolution) and nothing else. No public internet. No other cluster services. No databases directly. Backends are only accessible via the gateway, which enforces tool policies before forwarding.

One DNS note: DNS is a common exfiltration channel because UDP/53 is often allowed where TCP/443 is not. An adversarial agent that can make DNS lookups can exfiltrate data by encoding it in the query hostname (e.g., `<base64-of-secret>.attacker.com`). The counter-measure is to scope DNS access to the cluster-internal resolver (CoreDNS at its cluster IP) and have the network policy deny direct UDP/53 to the internet. By default, CoreDNS often forwards external queries to upstream resolvers, so this control alone does not prevent external domain resolution; pair it with DNS-layer allowlists/monitoring and explicit CoreDNS upstream restrictions where required.

### Kubernetes with gVisor

Since eBPF network policy doesn't work on gVisor pods, you enforce at the hypervisor/VPC level. On GKE, this means VPC firewall rules that constrain egress from the gVisor node pool's IP range to the gateway's IP. On AKS with pod sandboxing, it's network security groups on the subnet. It's less fine-grained than per-pod Cilium policies but achieves the same structural guarantee.

### Standalone VM (Firecracker / QEMU)

For non-Kubernetes deployments, the microVM's network interface is attached to a virtual network that has no route to the internet and only a route to the gateway's IP or CIDR. The hypervisor host doesn't expose routing that would let the VM reach other destinations:

```bash
# Host setup for a Firecracker agent microVM
# Creates a tap interface for the microVM with only a route to the gateway
ip tuntap add tap0 mode tap
ip addr add 169.254.100.1/30 dev tap0
ip link set tap0 up
# Only route: microVM -> gateway
ip route add 10.100.0.5/32 via 169.254.100.2  # gateway IP
# iptables: drop all other forwarding from tap0
iptables -A FORWARD -i tap0 -d 10.100.0.5 -j ACCEPT
iptables -A FORWARD -i tap0 -j DROP
```

The microVM sees a network with exactly one reachable destination: the gateway. The agent can call `connect()` to anything it wants; unless it's the gateway IP, the hypervisor drops the packet.

### The vsock path for Firecracker

One subtlety specific to Firecracker: Firecracker supports a vsock (virtio socket) device that provides a Unix-domain-socket-like path between the microVM and the VMM host process. This can be used to route the agent's tool calls through an in-process proxy on the host, rather than through a network interface at all.

The advantage: vsock bypasses the virtual network stack entirely. The agent makes tool calls to a vsock address (e.g., `vsock://2:1234`); the VMM host receives them via the vsock device and forwards to the gateway. Network sniffing inside the microVM cannot capture vsock traffic because it's not network traffic.

This is particularly useful for high-security deployments where you're worried about network traffic analysis inside the VM. The tool calls look, from inside the VM, like writes to a character device.

---

## The gateway as sidecar: co-located enforcement

One deployment pattern worth discussing explicitly because it changes the latency math: running the gateway as a sidecar in the same pod (Kubernetes) or on the same host (VM/Firecracker) as the agent.

The case for co-location: gateway enforcement currently adds 5-30ms per tool call, depending on Redis round-trip time and network topology. For agents with high call rates, that adds up. If you co-locate the gateway with the agent — pod sidecar, host process, or in the same Firecracker VM (though that last one has security tradeoffs) — the enforcement round-trip drops to sub-millisecond.

The case against: if the gateway runs in the same pod as the agent, a container escape that compromises the agent pod also potentially compromises the gateway. The gateway's security properties depend on running outside the agent's trust boundary.

My recommendation: co-locate the gateway as a sidecar when latency is the primary constraint and you have strong container isolation (gVisor or Kata). The sidecar gateway connects to Redis and the audit ledger as normal; it just happens to be on the same node, using localhost networking, rather than across the cluster. The enforcement logic is unchanged; the trust boundary is slightly weakened. For high-assurance workloads, run the gateway in a separate pod/namespace.

```yaml
# Sidecar pattern
spec:
  containers:
  - name: agent
    image: your-registry/agent:latest
    env:
    - name: EUNO_GATEWAY_URL
      value: "http://localhost:8080"
  - name: gateway
    image: your-registry/tool-gateway:latest
    ports:
    - containerPort: 8080
    env:
    - name: REDIS_URL
      valueFrom:
        secretKeyRef:
          name: gateway-config
          key: redis-url
    - name: AUDIT_DB_URL
      valueFrom:
        secretKeyRef:
          name: gateway-config
          key: audit-db-url
```

Network policy in this case: the agent can only reach `localhost:8080` (its sidecar gateway); no direct egress. The gateway sidecar has egress to Redis and the audit ledger, but the agent cannot reach those services directly.

---

## Identity and the "secret zero" problem

The hardest operational problem in agent sandboxing is: how does the agent get its capability token without there being a pre-placed secret in the environment? If you bootstrap the agent by mounting a JWT into the container, you've just pushed the problem back one level — now the orchestrator needs to hold the JWT, and if the orchestrator is compromised, every token it mounts is compromised.

The solution is workload identity. The agent shouldn't authenticate with a pre-issued token; it should authenticate with an attestation of its own identity that the runtime environment provides and the capability issuer can verify.

In Kubernetes, this is workload identity federation:
1. The pod's service account has a projected token from the Kubernetes API server
2. The capability issuer accepts that projected token as a client credential
3. The issuer verifies the token against the Kubernetes OIDC discovery endpoint
4. If the service account is in the issuance policy, the issuer mints an agent capability token
5. The agent uses the minted token for gateway calls

The agent never holds a long-lived credential. The only credential it starts with is the short-lived Kubernetes projected service account token, which is automatically rotated and tied to the pod's identity. If the pod is compromised, rotating the service account invalidates the projected tokens immediately.

For non-Kubernetes environments (Firecracker on bare metal, VMs), SPIFFE/SPIRE fills this role. SPIRE's workload attestor can verify a process's identity based on its UID, the path of its executable, and attestation of the hosting environment (AWS instance identity document, Google Cloud attestation, TPM-based attestation for bare metal). The agent's runtime calls the SPIFFE workload API to get a short-lived SVID; the capability issuer accepts that SVID as authentication; the issuer mints a capability token.

Neither of these is free to set up. But the alternative — managing long-lived secrets per agent deployment — scales badly and has a well-understood failure mode (credential sprawl, eventual leak). Workload identity is the operational solution that actually addresses the "secret zero" problem at scale.

---

## Audit and observability across the stack

One thing that gets complicated when you have strong sandboxing is observability. The whole point of the sandbox is that the agent can't affect things outside its boundary — but your monitoring system needs to be able to observe things inside the sandbox.

The layers:

**Gateway audit log**: This is your primary source of truth, as described in [post 11 (tamper-evident audit logs)](./11-tamper-evident-audit-logs.md). Every tool call the agent makes — every ALLOW and DENY decision — is in the OCSF audit record, HMAC-chained and timestamped. This data comes from the gateway, which is outside the sandbox, so you know it hasn't been tampered with by the agent.

**Host-level eBPF observability**: For sandboxes where eBPF works (plain containers, Kata Containers), you can run Falco or Tetragon on the host node to observe anomalous agent behavior: unexpected subprocess spawns, unexpected file opens, blocked syscall attempts. This data comes from the host kernel, outside the agent's trust domain.

**Application logging**: The agent itself should emit structured logs, but treat these as untrusted operational data, not security-critical evidence. An agent that's been compromised can write misleading logs. Use application logs for debugging and performance analysis; use the gateway audit log for security evidence.

**Resource usage metrics**: cgroup-level CPU/memory metrics (available via the Kubernetes metrics API or cAdvisor) can indicate anomalous behavior — an agent that's suddenly using 100% CPU might be mining cryptocurrency or running an exploit. Set resource limits tightly and alert on sustained limit approach.

One place I've seen teams struggle: piping the agent's stdout/stderr directly to a shared log aggregator without considering that the agent can write to stdout. An adversarial agent that knows it's being logged can write carefully crafted log entries to confuse monitoring systems or cause log injection. Log output from the agent process should be sanitized before being sent to structured logging systems. The gateway audit log, which the agent cannot write to directly, is the canonical evidence record.

---

## Pulling it together: environment-specific recipes

Let me give concrete guidance for each deployment scenario, because the right choices differ meaningfully.

### Cloud Kubernetes (EKS / GKE / AKS)

**Minimum baseline:**
- Pod security context: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: drop: ALL`
- Custom seccomp profile (via `seccompProfile.type: Localhost` and `seccompProfile.localhostProfile: profiles/agent-seccomp.json`) blocking `ptrace`, `process_vm_readv`, `perf_event_open`
- Cilium NetworkPolicy with default-deny egress, allow only gateway + cluster DNS
- Resource limits: set CPU and memory limits; enable LimitRange in the agent namespace

**Elevated isolation (recommended for production agent workloads):**
- RuntimeClass: `gvisor` (GKE) or `kata-mshv-vm-isolation` (AKS)
- Dedicated node pool for agent workloads with node taints (`dedicated=agent:NoSchedule`)
- Pod anti-affinity to prevent agents from co-scheduling on the same node
- VPC-level firewall rules as the enforcement backstop (not just K8s NetworkPolicy)
- SPIFFE/SPIRE or cloud-native workload identity (GKE Workload Identity, AKS Workload Identity, EKS IRSA) for token acquisition

**High assurance (sensitive workloads, external data sources):**
- RuntimeClass: Kata Containers on AKS, or self-managed Kata on EKS/GKE
- Separate VPC/VNet subnet for agent workloads, with NSG/SG enforcing egress to gateway only
- Falco or Tetragon for host-level behavioral monitoring
- gateway deployed in separate namespace with separate RBAC, network policy allowing only gateway → Redis → audit DB paths

### Standalone VM or bare-metal (non-Kubernetes)

**Docker-based (development / low sensitivity):**
- `--security-opt seccomp=agent-seccomp.json` — custom profile
- `--cap-drop ALL` — drop all Linux capabilities
- `--read-only` — read-only root filesystem, tmpfs for `/tmp`
- `--network` — dedicated network; `--add-host` for gateway only, no default route to internet
- `--user 1000:1000` — non-root

**Firecracker microVM (production / high sensitivity):**
- One microVM per agent session; destroy after session completes
- Virtual network with single route to gateway IP; iptables on hypervisor host to enforce
- SPIFFE/SPIRE for workload identity attestation
- vsock for tool call proxying (if sub-millisecond tool call latency is required)
- Minimal rootfs (Alpine-based, < 50MB); no package manager, no shell if possible

**QEMU/KVM with full VM (highest isolation, highest overhead):**
- Separate kernel per agent session
- Virtio-net attached to isolated bridge; host iptables enforces gateway-only egress
- Snapshot/restore for fast session start (pre-warmed VM snapshot)
- TPM-backed attestation (if hardware supports it) for identity

### Edge / IoT environments

Edge is a different problem. You're often on hardware that doesn't support KVM, can't run gVisor (no x86-64), and has limited memory. The sandboxing options are more limited.

The viable path for constrained edge:
- Seccomp filter + AppArmor/SELinux MAC policy (available on modern Linux even on ARM)
- Network namespace isolation via `unshare --net` with a veth pair to a host-side proxy
- The host-side proxy *is* the gateway interface — the agent has no network interface except a veth that terminates in a controlled proxy process on the host
- No microVM overhead; instead, rely on MAC policies and seccomp to restrict the agent's syscall surface

---

## The honest limitations

I want to be clear about what this architecture doesn't protect you against.

**Timing side channels**: An agent running in a shared-kernel environment can potentially infer information about other workloads via timing attacks on shared resources (CPU caches, memory bandwidth). gVisor and Kata Containers mitigate this significantly but don't fully eliminate it. For workloads where covert channels between tenants are a concern, physical isolation (separate hosts per tenant) is the only complete solution.

**Supply chain compromises in the base image**: The agent's base container image is part of your TCB. A compromised base image that pre-installs a rootkit can escape many of the above controls. Image signing (Cosign, Notary v2), admission control (OPA/Gatekeeper, Kyverno), and regular image scanning are your defense here.

**Gateway as single point of trust**: Everything above assumes the gateway is trustworthy. If the gateway itself is compromised, an attacker can grant arbitrary tool permissions. The gateway's security depends on correct deployment (mTLS for gateway-to-backend calls, proper Redis HA configuration as described in the gateway bootstrap, KMS-backed signing keys). [Post 29 on air-gapped deployments](../../blogs/29-air-gapped-ai-governance.md) covers the operator controls that protect the gateway itself.

**The agent process's own memory**: If the agent's process is compromised, an attacker has access to everything in that process's memory: in-flight tool arguments, response data, the session token. Seccomp and network controls prevent the attacker from *exfiltrating* that data, but the data is still accessible to the compromised process. Per-invocation tokens with tight TTLs (as opposed to long-lived session tokens) limit the blast radius.

---

## Summary: the non-negotiable controls

If you're starting from zero and need to prioritize, here's the ordering I'd use:

1. **Network egress lockdown first.** The most dangerous thing an adversarial agent can do is reach a backend directly, bypassing the gateway. Lock down egress to gateway-only before you do anything else. This is a firewall rule or network policy; it takes an hour to implement and provides enormous protection.

2. **Read-only filesystem + non-root.** An agent that can't write to the filesystem can't install backdoors or modify its own code. Running non-root with no capabilities eliminates most local privilege escalation paths.

3. **Custom seccomp profile.** Block `ptrace`, `process_vm_readv`, and `perf_event_open` at minimum. The Docker default seccomp profile does some of this; a custom profile hardened for your specific runtime does it better.

4. **Workload identity for token acquisition.** Don't mount long-lived tokens into the environment. Use projected service account tokens (Kubernetes) or SPIFFE/SPIRE (non-Kubernetes) to get capability tokens on demand with short TTLs.

5. **gVisor or Kata Containers for production agent workloads.** Once the basics are in place, upgrade to kernel or hypervisor isolation for production. The compatibility and performance tradeoffs are manageable; the isolation improvement is significant.

6. **eBPF behavioral monitoring (where compatible).** Falco or Tetragon on the host gives you visibility into what the agent process is actually doing, outside the agent's trust domain. Wire alerts to your SIEM.

The gateway handles policy enforcement and produces your audit evidence. The OS and VM layer ensures that the gateway is the *only* path for the agent to affect the outside world. Both layers are necessary. Neither is sufficient alone.

---

*The companion technical reference for the concepts described here is [`docs/sandboxing.md`](../sandboxing.md), which covers the detailed reference architecture including the Kubernetes RBAC configuration, SPIFFE/SPIRE integration patterns, and the Helm chart configuration for the k8s/helm/euno umbrella chart. For deployment-specific guidance, see [`docs/DEPLOYMENT.md`](../DEPLOYMENT.md) and the cloud-specific guides ([`docs/deploy-eks.md`](../deploy-eks.md), [`docs/deploy-gke.md`](../deploy-gke.md)).*

*Previous post in the architecture series: [post 14 (AGT: defense in depth)](./14-agt-defense-in-depth.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full index.*
