# Comprehensive Mermaid Diagram Set: Capability‑Native Agent Governance

Three diagram sets follow — each tailored to a distinct audience. Every diagram uses valid Mermaid syntax, labels entities and data objects explicitly, and marks trust boundaries via subgraphs. Azure services appear as reference implementations with generic alternatives noted in labels. 


## SET A — Engineering Implementation Diagrams

These diagrams carry field-level detail on data objects, cryptographic operations, and protocol flows for implementation engineers. 


### A1 — End‑to‑End System Architecture
```mermaid
flowchart LR
    subgraph Enterprise["Enterprise Domain - Azure Reference"]
        IdP["Identity Provider - (Entra ID or any OIDC IdP)"]
        Issuer["Capability Issuer - policy eval + token minting - signs via Key Vault or HSM"]
        Agent["AI Agent - DID identity + keypair - sandboxed runtime"]
        Attenuator["Attenuator - issues subset tokens - enforces no_new_privs"]
        Gateway["Tool Gateway - Reference Monitor - (APIM validate-jwt or equivalent)"]
        Audit["Audit Ledger - append-only tamper-evident - (Azure Monitor or any SIEM)"]
        Service["Protected Service - API - DB - Files"]
    end

    subgraph External["External or Partner Domain"]
        ExtIssuer["Partner Issuer - Partner DID authority"]
        ExtAgent["External Agent - DID identity"]
        ExtService["External API"]
    end

    subgraph TrustInfra["Decentralized Trust Layer"]
        DIDReg["DID Registry - resolve public keys - did:web via DNS or did:ion"]
        RevList["Revocation Service - status list or CRL"]
    end

    IdP -->|"OIDC token: sub roles aud exp"| Issuer
    Issuer -->|"Capability JWT or VC: sub=AgentDID - iss actions resources constraints exp jti sig"| Agent
    Agent -.->|"delegation request: subset of parent token"| Attenuator
    Attenuator -.->|"child token: narrower scope"| Agent
    Agent -->|"tool request + token + DPoP proof"| Gateway
    Gateway -->|"authorized request"| Service
    Gateway -.->|"DENY: no token or wrong scope"| Agent
    Gateway -->|"audit event"| Audit

    ExtIssuer -->|"Partner VC with capabilities"| ExtAgent
    ExtAgent -->|"request + Partner VC"| Gateway
    Gateway -.->|"resolve Partner DID for pubkey"| DIDReg
    Gateway -.->|"check revocation status"| RevList
    Agent -->|"cross-org request + Enterprise VC"| ExtService
    ExtService -.->|"resolve Enterprise DID for pubkey"| DIDReg
    ExtService -.->|"check status"| RevList
```
Legend:
|Symbol|Meaning|
| --- | --- |
|Solid arrow|Primary data flow (label shows data object and key fields)|
|Dashed arrow|Verification / lookup flow|
|Subgraph boundary|Trust boundary — components inside share a trust domain|

|Data Object|Key Fields|
| --- | --- |
|OIDC Token|sub (userID), roles, aud, exp, iss (IdP)|
|Capability Token (JWT/VC)|sub (Agent DID), iss (Enterprise DID), actions[], resources[], constraints{ttl, max_calls, redact}, exp, jti (unique ID), signature|
|DID Document|id (DID), verificationMethod[] (public keys), service[] (endpoints for registry, revocation), authentication[]|
|Audit Log Event|timestamp, agentDID, capabilityId, action, resource, outcome (allow/deny), parentCapId (if delegated)|

The validate-jwt policy on Azure APIM enforces existence and validity of the JWT extracted from a specified HTTP header, checking issuer, audience, expiration, required claims, and signature against configured signing keys【6†L16-L22】. Any API gateway with JWT validation (AWS API Gateway + Lambda Authorizer, Envoy with JWT filter, NGINX with auth module) serves the same role. 


### A2 — Identity and Capability Issuance Flow
```mermaid
sequenceDiagram
    autonumber
    participant User
    participant IdP as OIDC IdP (Entra ID)
    participant Issuer as Capability Issuer
    participant HSM as Key Vault or HSM
    participant Agent as Agent Instance

    User->>IdP: Authenticate via OAuth 2.0 / OIDC
    IdP-->>User: Authorization code
    User->>Issuer: Request agent creation with auth code and agent type
    Issuer->>IdP: Exchange code for tokens at token endpoint
    IdP-->>Issuer: id_token with sub roles groups and access_token
    Issuer->>Issuer: Evaluate policy and map user roles to capability set
    Note over Issuer: Load Agent Capability Manifest template - Intersect with user actual permissions
    Issuer->>Issuer: Build token payload - sub=AgentDID iss=EnterpriseDID - actions resources constraints exp jti
    Issuer->>HSM: Sign payload digest via ECDSA or Ed25519
    Note over HSM: Key Vault does not hash content - Hash locally then sign the digest
    HSM-->>Issuer: JWS signature
    Issuer->>Issuer: Assemble signed JWT/VC as header.payload.signature
    Issuer-->>Agent: Capability Token (signed JWT/VC)
```

```
Capability Token payload example: 
{
  "iss": "did:web:enterprise.example.com",
  "sub": "did:web:enterprise.example.com:agents:triage-123",
  "aud": "https://apim.enterprise.example.com",
  "exp": 1745678400,
  "jti": "8457e9ab-1234-abcd-ef01-567890abcdef",
  "cap": {
    "actions": ["read", "search"],
    "resources": ["logs://cluster/A/*"],
    "constraints": {
      "ttl_seconds": 900,
      "redact": ["pii", "secrets"],
      "max_calls": 100
    }
  },
  "no_new_privs": true
}
```

The signing step uses Azure Key Vault's sign operation, which creates a signature from a digest — the hash is computed locally before calling the Key Vault API【5†L287-L289】. On AWS the equivalent is KMS Sign; on GCP it is Cloud KMS asymmetricSign. 


### A3 — Tool Invocation and Enforcement Flow
```mermaid
sequenceDiagram
    autonumber
    participant Agent
    participant Gateway as Tool Gateway (APIM)
    participant Resolver as DID or JWKS Resolver
    participant Rev as Revocation Service
    participant Service as Protected API or Tool

    Agent->>Gateway: HTTPS request - Authorization: Bearer JWT/VC - DPoP: signed nonce - Body: tool parameters
    Gateway->>Resolver: Fetch issuer public key from JWKS or DID Document
    Resolver-->>Gateway: Public key (cached and refreshed periodically)
    Gateway->>Gateway: Step 1 Verify JWS signature against public key
    Gateway->>Gateway: Step 2 Validate standard claims iss aud exp
    Gateway->>Gateway: Step 3 Enforce required claims match requested action and resource
    Gateway->>Gateway: Step 4 Verify DPoP proof agent key matches token sub DID
    Gateway->>Rev: Step 5 Check revocation status of jti or agentDID
    Rev-->>Gateway: Status active or revoked

    alt Token invalid or expired or insufficient scope or revoked
        Gateway-->>Agent: HTTP 401 or 403 DeniedAction
        Note over Gateway: Log agentDID capId action resource outcome=DENIED reason ts
    else All checks pass
        Gateway->>Service: Forward authorized request with downstream context
        Service-->>Gateway: Response data
        Gateway-->>Agent: HTTP 200 Tool result
        Note over Gateway: Log agentDID capId action resource outcome=ALLOWED ts
    end
```
Enforcement semantics: APIM's validate-jwt policy checks that the token was issued by a trusted issuer, targets the correct audience, has not expired, and contains required claims matching the requested operation. Required claims configured via ensure that only tokens explicitly listing the needed action scope pass validation. Tokens lacking the correct scope are rejected with the configured failed-validation-httpcode (default 401)【6†L51-L52】【6†L68-L70】. 


### A4 — Delegation and Attenuation Flow
```mermaid
sequenceDiagram
    autonumber
    participant Parent as Parent Agent DID_P
    participant Attenuator
    participant HSM as Key Vault or HSM
    participant Child as Child Agent DID_C
    participant Gateway as Tool Gateway

    Parent->>Attenuator: Delegate request - parent_cap=jti123 - child=DID_C - req_actions=[read] req_res=[logs:projectX] req_ttl=300
    Attenuator->>Attenuator: Retrieve parent capability jti123
    Attenuator->>Attenuator: Invariant check: requested subset of parent?
    Note over Attenuator: Parent has actions=[read search] - resources=[logs://cluster/A/*] ttl=900 - Child requests actions=[read] - resources=[logs://cluster/A/node1] ttl=300 - Result VALID strict subset

    alt Requested scope exceeds parent
        Attenuator-->>Parent: DENIED no_new_privs violation
        Note over Attenuator: Log delegation_denied parent_cap_id reason
    else Valid subset confirmed
        Attenuator->>Attenuator: Build child token payload with narrower scope
        Attenuator->>HSM: Sign child token digest
        HSM-->>Attenuator: Signature
        Attenuator-->>Child: Delegated Capability Token child_cap=jti456
        Note over Attenuator: child token includes parent_cap_id for audit linkage
        Attenuator->>Attenuator: Log CapabilityDelegated parent=jti123 child=jti456
    end

    Child->>Gateway: Tool request with delegated token
    Gateway->>Gateway: Validate child token same enforcement as A3
    Note over Gateway: Child token authorizes [read] on [logs://cluster/A/node1] only - Any request outside this scope results in DENIED
```
Attenuation rules:
|Parent Capability|Attenuation Allowed|Attenuation Denied|
| --- | --- | --- |
|actions: [read, search]|actions: [read] (subset)|actions: [read, write] (adds write)|
|resources: [logs://cluster/A/*]|resources: [logs://cluster/A/node1] (narrower)|resources: [logs://cluster/B/*] (different resource)|
|ttl: 900|ttl: 300 (shorter)|ttl: 1800 (longer)|
|max_calls: 100|max_calls: 50 (lower)|max_calls: 200 (higher)|


### A5 — Revocation and Kill‑Switch Propagation Flow
```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant Issuer as Capability Issuer or Registry
    participant Rev as Revocation Store (Redis or Status List)
    participant Gateway as Tool Gateway
    participant Agent

    rect rgb(255, 240, 240)
        Note over Admin,Agent: Scenario Targeted Revocation
        Admin->>Issuer: Revoke capability cap_id=jti123
        Issuer->>Rev: Mark jti123 as revoked
        Note over Rev: Entry jti=jti123 status=revoked revokedAt reason
        Issuer->>Issuer: Log CapabilityRevoked cap_id revokedBy reason ts
        Gateway->>Rev: Periodic poll or push notification delta sync
        Rev-->>Gateway: Updated status jti123 REVOKED
        Gateway->>Gateway: Cache revocation locally for fast lookup
        Agent->>Gateway: Tool request with revoked token jti123
        Gateway->>Gateway: Check jti against revocation cache and find match
        Gateway-->>Agent: HTTP 401 Token revoked
    end

    rect rgb(255, 230, 230)
        Note over Admin,Agent: Scenario Emergency Kill Switch
        Admin->>Gateway: Kill session agentDID=did:web:...triage-123
        Gateway->>Gateway: Add agentDID to session blacklist
        Note over Gateway: All subsequent requests from this DID get immediate 403
        Agent->>Gateway: Any tool request
        Gateway-->>Agent: HTTP 403 AGENT_SESSION_KILLED
        Gateway->>Gateway: Log SessionKilled agentDID killedBy ts
    end
```
Revocation models compared:
|Model|Latency|Complexity|Best For|
| --- | ---- | ---- | ---- |
|Short TTL (5–15 min)|Passive; expires naturally|Low — no active revocation needed|Default baseline; reduces window of abuse|
|Revocation list (centralized)|Seconds (push) to minutes (poll)|Medium — requires distributed cache (e.g., Azure Cache for Redis)|Targeted token invalidation|
|DID Document status endpoint|Depends on resolution method|Higher — requires registry service discoverable via DID Document|Cross-org credential revocation|
|Kill-switch (session blacklist)|Immediate (in-memory)|Low — simple set lookup at Gateway|Emergency response|


## SET B — Security Review and Threat‑Modeling Diagrams

These diagrams emphasize trust boundaries, attack surfaces, and containment mechanisms for security architects and threat-modeling sessions. 


### B1 — Trust Boundaries and Attack Surfaces
```mermaid
flowchart TB
    subgraph Untrusted["UNTRUSTED ZONE"]
        user_input["Human and External Inputs - prompts and web data"]
        agent_process["Agent Process - LLM reasoning - untrusted decisions"]
        ext_agent["External Agent or API - untrusted identity"]
    end

    subgraph TCB["TRUSTED COMPUTING BASE"]
        idp["Central IdP"]
        issuer["Capability Issuer"]
        gateway["Secure Gateway - Reference Monitor"]
        sandbox["Sandbox - no default net or fs - seccomp and AppArmor"]
        monitor["Monitoring and SIEM"]
        killswitch["Kill Switch - admin only - outside agent runtime"]
    end

    subgraph Resources["PROTECTED RESOURCES"]
        data_store["Enterprise Data and Services"]
    end

    user_input --> agent_process
    ext_agent -->|"VC + DID"| gateway
    agent_process -->|"action + token"| gateway
    gateway -->|"ALLOW"| data_store
    gateway -.->|"DENY"| agent_process
    gateway --> monitor
    idp --> issuer
    issuer --> agent_process
    sandbox -.->|"constrains agent process"| agent_process
    monitor -.-> admin["Security Team"]
    admin -.-> killswitch
    killswitch -.->|"terminate session"| gateway
```
Attack surfaces at each trust boundary crossing:
|Crossing Point|Threat|Mitigation|
| --- | --- | --- |
|User Input to Agent|Direct prompt injection|Capability enforcement ensures injected instructions cannot trigger unauthorized actions|
|External Data to Agent|Indirect prompt injection via hidden instructions in documents|Agent may be influenced but lacks capability tokens for unauthorized operations|
|Agent to Gateway|Token forgery, replay, scope escalation|Signature verification, DPoP proof-of-possession, strict scope matching【6†L16-L22】|
|External Agent to Gateway|Compromised partner credential|Issuer DID verification, revocation checking, trust anchor validation|
|Gateway to Protected Resources|Confused deputy: Gateway acting on attacker behalf|Gateway enforces object-specific capability tokens not identity-based; each action requires a matching token|


### B2 — Token Replay vs Proof‑of‑Possession Defense
```mermaid
sequenceDiagram
    autonumber
    participant Legit as Legitimate Agent with key
    participant Attacker as Attacker without key
    participant GW as Tool Gateway

    rect rgb(230, 255, 230)
        Note over Legit,GW: Normal flow Agent proves key ownership
        Legit->>GW: Tool request + Capability JWT + DPoP signature
        Note right of Legit: DPoP header contains - htm POST htu /api/tool iat jti - signed with Agent DID private key
        GW->>GW: 1 Verify JWT signature with issuer key
        GW->>GW: 2 Verify DPoP signature with agent DID public key
        GW->>GW: 3 Confirm DPoP key thumbprint matches JWT sub claim
        GW-->>Legit: 200 OK Action executed
    end

    rect rgb(255, 230, 230)
        Note over Attacker,GW: Attack Stolen token replayed
        Attacker->>GW: Same JWT stolen + forged DPoP attempt
        Note right of Attacker: Attacker cannot produce valid DPoP - because they lack DID-A private key
        GW->>GW: 1 JWT signature valid issuer key matches
        GW->>GW: 2 DPoP signature INVALID wrong key
        GW-->>Attacker: 401 Unauthorized PoP check failed
        Note over GW: Log DeniedAction reason=invalid_dpop ts
    end
```
Security rationale: Without proof-of-possession, a stolen bearer token grants the attacker full authority for the token's lifetime. With DPoP, the attacker must also possess the agent's private key to produce a valid signature. Since the private key is held in protected memory (never exposed to the LLM's token stream), token theft alone is insufficient for exploitation. 


### B3 — Confused Deputy Containment via Constrained Delegation
```mermaid
flowchart LR
    P["Parent Agent - capabilities A B C"]
    ATT["Attenuator - verifies subset rule"]
    C["Child Agent - capabilities A B only"]
    GW["Tool Gateway"]
    RA["Resource A - ALLOWED"]
    Denied_C["Action C - DENIED 403"]
    Denied_D["Action D - DENIED 403"]

    P -->|"delegates A and B only"| ATT
    ATT -->|"issues child token for A B"| C
    C -->|"request action A with valid token"| GW
    GW -->|"token covers A"| RA
    C -->|"request action C not in token"| GW
    GW -.->|"token lacks C"| Denied_C
    C -->|"request action D never existed"| GW
    GW -.->|"token lacks D"| Denied_D
```
Blast radius analysis:
|Scenario|Without Capability Model|With Capability Model|
| --- | --- | --- |
|Child agent compromised via prompt injection|Full access to parent permissions A B C plus potentially ambient credentials|Access limited to delegated subset A B only|
|Attacker tries to escalate via child|Can invoke any API the parent identity has access to|Gateway rejects any request outside A B|
|Maximum damage|Unlimited within parent identity scope|Bounded to explicitly delegated actions on specific resources|

This is the mechanical solution to the confused deputy problem: the child agent's authority is provably bounded by the parent's explicit delegation, not by the child's claimed identity or the parent's ambient privileges. 


### B4 — Incident Response: Detection to Containment to Forensics
```mermaid
flowchart TB
    subgraph Detection["1 Detection"]
        Alert["Sentinel or SIEM Alert - spike in DeniedAction events - or anomalous tool-call pattern"]
        Monitor["Monitoring Dashboard - rate of denied vs allowed - agent behavior anomaly"]
    end

    subgraph Containment["2 Containment within seconds"]
        Kill["Kill Switch Activation - admin API kill session"]
        Revoke["Token Revocation - add jti to revocation list"]
        Isolate["Network Isolation - block agent pod egress"]
    end

    subgraph Forensics["3 Forensic Analysis"]
        AuditGraph["Capability Audit Graph - reconstruct authority chain"]
        TraceBack["Trace action to capId - to parentCapId to issuer - to principal"]
        Evidence["Evidence Package - signed audit records - verifiable via enterprise pubkey"]
    end

    Alert --> Kill
    Monitor --> Kill
    Kill --> Revoke
    Kill --> Isolate
    Revoke --> AuditGraph
    Isolate --> AuditGraph
    AuditGraph --> TraceBack
    TraceBack --> Evidence
```
Forensic query examples supported by the Capability Audit Graph:
|Question|How the CAG Answers It|
| --- | --- | 
|What did the compromised agent do?|Query all ActionExecuted events where agentDID = compromised_agent|
|Who authorized this agent?|Trace CapabilityIssued event via issuedBy field to human principal DID|
|Could the agent have accessed Resource X?|Check if any capability with resource = X was ever issued to this agent|
|Did any sub-agent exceed parent authority?|Compare CapabilityDelegated events: verify child scope is a subset of parent scope for every delegation|
|Is the evidence tamper-proof?|Each audit record is signed with the enterprise Key Vault key — verifiable by any party with the public key【5†L287-L289】|


## SET C — Architecture Communication Diagrams

Simplified diagrams for architects, leadership, and cross-functional stakeholders. Focus on roles, responsibilities, and data flows rather than low-level mechanics. 


### C1 — Capability‑Native Governance Overview
```mermaid
flowchart LR
    user["User or Owner"]
    idp["Identity System - (Azure AD or any IdP)"]
    issuer["Capability Issuer"]
    agent["AI Agent"]
    gateway["Secure Gateway"]
    service["Enterprise Service"]
    audit["Audit Log"]

    user --> idp
    idp --> issuer
    issuer -->|"gives capability token"| agent
    agent -->|"requests action with token"| gateway
    gateway -->|"verifies and forwards"| service
    gateway -.->|"blocks if not authorized"| agent
    gateway --> audit
```
Key message for stakeholders: The agent never has direct access to enterprise resources. Every action must pass through the Secure Gateway, which mechanically verifies the agent's token before allowing any operation. If an agent is tricked by malicious input, it can attempt unauthorized actions — but those attempts are automatically blocked and logged. 


### C2 — Agent Authorization Lifecycle
```mermaid
sequenceDiagram
    autonumber
    actor User
    participant IdP as Identity Provider
    participant Issuer as Cap Issuer
    participant Agent
    participant Gateway as Secure Gateway

    User->>IdP: Sign in and approve agent
    IdP-->>Issuer: User identity and roles
    Issuer-->>Agent: Capability token with scope limits
    Agent->>Gateway: Action request with token

    alt Token valid and allows action
        Gateway-->>Agent: Action executed
    else Token missing invalid or wrong scope
        Gateway-->>Agent: Access denied
    end
```
Stakeholder takeaway: This system converts the security question from "Will the AI follow its instructions?" to "Does the AI hold a valid token for this specific action?" — a question with a deterministic, verifiable answer. 


### C3 — Cross‑Organization Agent Trust via Verifiable Credentials
```mermaid
flowchart LR
    subgraph OrgA["Organization A"]
        issuerA["A Issuer - DID: did:web:a.example.com"]
        agentA["Agent A - DID: did:web:a.example.com:agents:007"]
    end

    subgraph OrgB["Organization B"]
        serviceB["Service B - Verifier"]
    end

    subgraph PublicTrust["Public Trust Layer"]
        DIDDoc["DID Documents - public keys and - service endpoints"]
    end

    issuerA -->|"1 Issue VC to Agent A - signed by Company A DID"| agentA
    agentA -->|"2 Present VC + proof of DID key"| serviceB
    serviceB -.->|"3 Resolve Company A DID - fetch public key from DID Doc"| DIDDoc
    serviceB -->|"4 Verify VC signature - 5 If trusted issuer grant access"| serviceB
```
How it works (for non-technical stakeholders): 
1. Organization A issues a digital credential to its agent, cryptographically signed by Organization A's identity.

2. The agent presents this credential to Organization B's service.

3. Organization B looks up Organization A's public key from a public registry (no direct connection to Organization A's identity system needed).

4. Organization B verifies the credential's authenticity using that public key.

5. If Organization B trusts Organization A as an issuer (pre-configured), access is granted.

Research on AI agents equipped with W3C DIDs and VCs demonstrates that this approach enables agents to prove ownership of their self-controlled DIDs for authentication purposes and establish various cross-domain trust relationships through the spontaneous exchange of their self-hosted DID-bound VCs. The same research reveals that security-critical procedures such as VC verification should not be orchestrated solely by the LLM — they must be implemented as deterministic external controls, reinforcing the core principle that enforcement belongs in the trusted computing base, not in the agent's reasoning layer.

---

## SET D — AGT Integration Diagrams

These diagrams show the layered defense model when integrating with an
in-process policy engine (e.g. Microsoft AGT) alongside the euno capability
gateway.

### D1 — High-Level Architecture: Sandbox and AGT Integration

Shows layered defense — AGT as inner guard, Sandbox + Gateway as outer guard.

```mermaid
flowchart LR
    subgraph SandboxBoundary["Agent Sandbox (Container or VM -- No Ambient Authority)"]
        direction TB
        LLM["LLM Reasoning Loop"]
        AGT["AGT Policy Engine (Inner Guard)"]
        LLM --> AGT
    end

    Issuer["Capability Issuer"]
    Gateway["Reference Monitor / Capability Proxy (Outer Guard)"]
    API["External API or Service"]
    Denied["BLOCKED (No valid token)"]
    SIEM["Monitoring and SIEM"]
    KillSwitch["Kill Switch (Admin-only, outside agent runtime)"]

    Issuer -->|"Signed capability tokens (actions, resources, TTL)"| SandboxBoundary
    SandboxBoundary -->|"Tool call with token"| Gateway
    Gateway -->|"Token valid and in scope"| API
    Gateway -.->|"Token missing or invalid"| Denied
    SandboxBoundary -.->|"Telemetry and logs"| SIEM
    Gateway -.->|"Allow and deny events"| SIEM
    KillSwitch -.->|"Terminate session"| Gateway
```

### D2 — Runtime Action Enforcement Flow

AGT evaluates intent (soft guard); Gateway enforces capability (hard guard).

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

    Note over AGT: Evaluates semantic intent, policy rules, trust score

    alt AGT blocks action
        AGT-->>Agent: DENY - blocked by in-process policy
    else AGT allows action
        AGT-->>Agent: ALLOW - proceed
        Agent->>Gateway: Tool request with capability token and DPoP proof

        Note over Gateway: Validates signature, claims, scope, DPoP, revocation

        alt Token valid and action within scope
            Gateway->>API: Forward authorized request
            API-->>Gateway: Response
            Gateway-->>Agent: Return result
        else Token invalid, expired, or revoked
            Gateway-->>Agent: HTTP 401 or 403 DENIED
        end
    end
```

### D3 — Control-Plane Lifecycle: Agent Creation and Sandbox Provisioning

```mermaid
sequenceDiagram
    autonumber
    participant User
    participant IdP as Identity Provider
    participant Issuer as Capability Issuer
    participant Platform as Agent Platform
    participant Sandbox as Sandbox Environment
    participant Agent as Agent Process

    User->>IdP: Authenticate (OAuth 2.0 / OIDC)
    IdP-->>Issuer: OIDC token (sub, roles, groups)
    Issuer->>Issuer: Map roles to capability set; mint signed tokens
    Issuer-->>Platform: Capability token set
    Platform->>Sandbox: Provision isolated sandbox (deny-all egress)
    Sandbox-->>Platform: Sandbox ready
    Platform->>Agent: Start agent; inject tokens; set proxy as sole egress
    Agent->>Agent: Initialize LLM runtime and AGT policy engine
```

### D4 — Incident and Enforcement Flow: Violation, Revocation, Kill-Switch

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Agent (in Sandbox)
    participant AGT as AGT (Inner Guard)
    participant Gateway as Reference Monitor (Outer Guard)
    participant SIEM as Security Ops / SIEM
    participant Admin as Admin or Automated Response

    Agent->>AGT: Execute tool action

    alt AGT detects policy violation
        AGT-->>Agent: BLOCKED
        AGT->>SIEM: Alert: policy violation
    else AGT passes
        Agent->>Gateway: External call with capability token

        alt Token invalid, expired, revoked, or out-of-scope
            Gateway-->>Agent: 401 / 403 DENIED
            Gateway->>SIEM: Alert: unauthorized action
            SIEM->>Admin: Escalation: possible compromised agent
            Admin->>Gateway: Engage KILL SWITCH
            Gateway-->>Agent: All further requests return 403 KILLED
        else Token valid and in scope
            Gateway->>Gateway: Log: ActionExecuted
            Gateway-->>Agent: Action executed successfully
        end
    end
```
