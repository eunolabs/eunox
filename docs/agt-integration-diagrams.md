## DIAGRAM 1: High-Level Architecture — Sandbox and AGT Integration
Shows layered defense: AGT as inner guard, Sandbox + Gateway as outer guard
```mermaid
flowchart LR
    subgraph SandboxBoundary["Agent Sandbox (Container or VM -- No Ambient Authority)"]
        direction TB
        LLM["LLM Reasoning Loop"]
        AGT["AGT Policy Engine<br/>(Inner Guard:<br/>semantic checks,<br/>anomaly detection,<br/>trust scoring)"]
        LLM --> AGT
    end

    Issuer["Capability Issuer<br/>(Mints scoped tokens<br/>at agent launch)"]
    Gateway["Reference Monitor<br/>Capability Proxy<br/>(Outer Guard:<br/>token verification,<br/>scope enforcement)"]
    API["External API<br/>or Service"]
    Denied["BLOCKED<br/>(No valid token)"]
    SIEM["Monitoring and SIEM<br/>(Azure Sentinel or equivalent)"]
    KillSwitch["Kill Switch<br/>(Admin-only,<br/>outside agent runtime)"]

    Issuer -->|"Signed capability tokens<br/>(actions, resources, TTL)"| SandboxBoundary
    SandboxBoundary -->|"Tool call with token"| Gateway
    Gateway -->|"Token valid and in scope"| API
    Gateway -.->|"Token missing or invalid"| Denied
    SandboxBoundary -.->|"Telemetry and logs"| SIEM
    Gateway -.->|"Allow and deny events"| SIEM
    KillSwitch -.->|"Terminate session"| Gateway
```
## DIAGRAM 2: Runtime Action Enforcement Flow
AGT evaluates intent (soft guard); Gateway enforces capability (hard guard)

Environment: Kubernetes (sidecar proxy) or non-K8s (host proxy)
```mermaid
sequenceDiagram
    autonumber
    participant User
    participant Agent as Agent (in Sandbox)
    participant AGT as AGT Policy Engine (Inner Guard)
    participant Gateway as Reference Monitor (Outer Guard)
    participant API as External API or Tool

    User->>Agent: Command or query
    Agent->>AGT: Propose tool action with context

    Note over AGT: AGT evaluates:<br/>- Semantic intent classifier<br/>- Policy rules (YAML/Rego/Cedar)<br/>- Trust score check<br/>- Content and loop detection

    alt AGT blocks action (policy violation)
        AGT-->>Agent: DENY - blocked by in-process policy
        Note right of AGT: Logged as policy violation.<br/>AGT alert sent to SIEM.<br/>No external call attempted.
    else AGT allows action
        AGT-->>Agent: ALLOW - proceed
        Note over Agent,Gateway: Agent sends request via sandbox proxy.<br/>No direct network access exists.<br/>(K8s: NetworkPolicy deny-all egress except proxy.<br/>Non-K8s: iptables or network namespace restriction.)
        Agent->>Gateway: Tool request with capability token and DPoP proof

        Note over Gateway: Gateway validates:<br/>1. Cryptographic signature (issuer key)<br/>2. Claims: iss, sub, aud, exp<br/>3. Action and resource match token scope<br/>4. Proof-of-possession (DPoP)<br/>5. Revocation status check

        alt Token valid and action within scope
            Gateway->>API: Forward authorized request
            API-->>Gateway: Response
            Gateway-->>Agent: Return result
            Note right of Gateway: Log: ActionExecuted<br/>(agentDID, capId, action, resource, ts)
        else Token missing, invalid, expired, or revoked
            Gateway-->>Agent: HTTP 401 or 403 DENIED
            Note right of Gateway: Log: DeniedAction<br/>(reason, agentDID, action, ts)<br/>Alert to SIEM if repeated
        end
    end
```
## DIAGRAM 3: Control-Plane Lifecycle — Agent Creation and Sandbox Provisioning
Shows identity issuance, sandbox setup, and capability injection
```mermaid
sequenceDiagram
    autonumber
    participant User
    participant IdP as Identity Provider (Entra ID or OIDC)
    participant Issuer as Capability Issuer
    participant Platform as Agent Platform (K8s controller or VM orchestrator)
    participant Sandbox as Sandbox Environment
    participant Agent as Agent Process

    User->>IdP: Authenticate (OAuth 2.0 or OIDC)
    IdP-->>Issuer: OIDC token (sub, roles, groups)

    Issuer->>Issuer: Policy evaluation:<br/>Map user roles to capability set<br/>Load Agent Capability Manifest template<br/>Intersect with user permissions

    Issuer->>Issuer: Mint signed tokens (JWT or VC)<br/>Sign via Key Vault or HSM

    Issuer-->>Platform: Capability token set for agent

    Platform->>Sandbox: Provision isolated sandbox
    Note over Sandbox: K8s: Create Pod with seccomp, AppArmor,<br/>NetworkPolicy deny-all, RuntimeClass<br/>(runc for standard, kata-vm-isolation for high-assurance).<br/>Non-K8s: Launch Firecracker microVM or Docker<br/>with --network=none --read-only --cap-drop=ALL.

    Sandbox-->>Platform: Sandbox ready (isolated, no ambient access)

    Platform->>Agent: Start agent inside sandbox
    Note over Platform,Agent: Inject capability tokens and identity.<br/>Configure proxy endpoint as sole egress path.<br/>Optionally initialize AGT as in-process monitor.

    Agent->>Agent: Initialize LLM runtime and AGT policy engine

    Note over Agent,Sandbox: Agent runs with ZERO default access.<br/>All external actions require valid capability token<br/>presented to the Reference Monitor.
```
## DIAGRAM 4: Incident and Enforcement Flow — Violation, Revocation, Kill-Switch
Shows dual-layer detection and escalation path
```mermaid
sequenceDiagram
    autonumber
    participant Agent as Agent (in Sandbox)
    participant AGT as AGT (Inner Guard)
    participant Gateway as Reference Monitor (Outer Guard)
    participant SIEM as Security Ops and SIEM
    participant Admin as Admin or Automated Response

    Agent->>AGT: Execute tool action (with prompt context)

    Note over AGT: AGT inspects content and intent

    alt AGT detects high-risk or disallowed content
        AGT-->>Agent: BLOCKED - policy violation (no external call made)
        AGT->>SIEM: Alert: AGT policy violation (goal hijack, loop, or content issue)
        Note over AGT,SIEM: AGT provides explainability:<br/>why the action was blocked,<br/>prompt context, trust score.
    else AGT finds no policy issue
        AGT-->>Agent: No intervention - action proceeds
        Agent->>Gateway: External call via sandbox proxy with capability token

        Note over Gateway: Gateway enforces capability scope

        alt Token invalid, expired, scope mismatch, or revoked
            Gateway-->>Agent: HTTP 401 or 403 - DENIED
            Gateway->>SIEM: Alert: Unauthorized action attempt
            Note over SIEM: SIEM correlates: repeated denials<br/>from same agent trigger escalation

            SIEM->>Admin: Escalation: possible compromised agent
            Admin->>Gateway: Engage KILL SWITCH (session blacklist)
            Gateway-->>Agent: All further requests return 403 KILLED
            Admin->>Admin: Revoke all tokens for this agent
            Note over Admin: Post-incident: review Capability Audit Graph<br/>to trace action to capId to issuer to principal

        else Token valid and action within scope
            Gateway->>Gateway: Log: ActionExecuted (for audit trail)
            Gateway-->>Agent: Action executed successfully
        end
    end
```