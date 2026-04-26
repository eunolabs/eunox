%% SET A1 — End to End Architecture (Engineering)
%% Legend: Solid arrows = data flow. Dashed arrows = verification or lookup. Subgraphs = trust boundaries.
flowchart LR
  subgraph EnterpriseDomain
    IdP[IdentityProvider_OIDC]
    Issuer[CapabilityIssuer]
    Agent[AgentRuntime_DID]
    Attenuator[Attenuator_no_new_privs]
    Gateway[ToolGateway_ReferenceMonitor]
    Audit[AuditLedger]
    Service[ProtectedService]
  end

  subgraph ExternalDomain
    ExtIssuer[PartnerIssuer_DID]
    ExtAgent[PartnerAgent_DID]
    ExtService[ExternalService]
  end

  subgraph TrustLayer
    DIDRegistry[DIDRegistry]
    Revocation[RevocationService]
  end

  IdP -->|OIDC_token_sub_roles_aud_exp| Issuer
  Issuer -->|CapabilityToken_sub_iss_actions_resources_exp_jti| Agent
  Agent -.->|delegate_subset| Attenuator
  Attenuator -.->|child_token_subset| Agent
  Agent -->|request_token_DPoP| Gateway
  Gateway -->|allow| Service
  Gateway -->|audit_event| Audit
  Gateway -.->|deny| Agent

  ExtIssuer -->|PartnerVC| ExtAgent
  ExtAgent -->|request_PartnerVC| Gateway
  Gateway -.-> DIDRegistry
  Gateway -.-> Revocation
  Agent -->|cross_org_request| ExtService
  ExtService -.-> DIDRegistry
%% SET A2 — Identity and Capability Issuance Flow (Engineering)
%% Legend: Sequence shows token minting and signing.
sequenceDiagram
  autonumber
  participant User
  participant IdP
  participant Issuer
  participant HSM
  participant Agent

  User->>IdP: authenticate
  IdP-->>User: auth_code
  User->>Issuer: create_agent(auth_code)
  Issuer->>IdP: exchange_code
  IdP-->>Issuer: id_token_sub_roles
  Issuer->>Issuer: policy_eval_to_capabilities
  Issuer->>HSM: sign_token_hash
  HSM-->>Issuer: signature
  Issuer-->>Agent: capability_token_JWT_or_VC
%% SET A3 — Tool Invocation and Enforcement (Engineering)
%% Legend: Gateway enforces signature scope TTL and revocation.
sequenceDiagram
  autonumber
  participant Agent
  participant Gateway
  participant Resolver
  participant Revocation
  participant Service

  Agent->>Gateway: request_with_token_and_DPoP
  Gateway->>Resolver: fetch_public_key
  Resolver-->>Gateway: public_key
  Gateway->>Gateway: verify_signature_and_claims
  Gateway->>Revocation: check_jti_status
  Revocation-->>Gateway: active_or_revoked

  alt invalid_or_revoked
    Gateway-->>Agent: deny_401_403
  else valid
    Gateway->>Service: forward_request
    Service-->>Gateway: response
    Gateway-->>Agent: result
  end
%% SET A4 — Delegation and Attenuation (Engineering)
%% Legend: Child capabilities must be strict subset of parent.
sequenceDiagram
  autonumber
  participant Parent
  participant Attenuator
  participant HSM
  participant Child
  participant Gateway

  Parent->>Attenuator: request_delegate_subset
  Attenuator->>Attenuator: verify_subset_rule

  alt violation
    Attenuator-->>Parent: deny_no_new_privs
  else ok
    Attenuator->>HSM: sign_child_token
    HSM-->>Attenuator: signature
    Attenuator-->>Child: delegated_token
  end

  Child->>Gateway: request_with_child_token
  Gateway->>Gateway: enforce_subset_scope
%% SET A5 — Revocation and Kill Switch (Engineering)
%% Legend: Revocation via jti list. Kill switch via session blacklist.
sequenceDiagram
  autonumber
  participant Admin
  participant Issuer
  participant Revocation
  participant Gateway
  participant Agent

  Admin->>Issuer: revoke_capability_jti
  Issuer->>Revocation: mark_revoked
  Gateway->>Revocation: sync_revocations
  Agent->>Gateway: request_with_revoked_token
  Gateway-->>Agent: deny_revoked

  Admin->>Gateway: kill_agent_session
  Agent->>Gateway: any_request
  Gateway-->>Agent: deny_killed
%% SET B1 — Trust Boundaries and Attack Surfaces (Security)
%% Legend: Left untrusted. Middle trusted computing base. Right protected resources.
flowchart TB
  subgraph Untrusted
    UserInput
    AgentProcess
    ExternalAgent
  end

  subgraph TCB
    IdP
    Issuer
    Gateway
    Sandbox
    Monitor
    KillSwitch
  end

  subgraph Resources
    DataServices
  end

  UserInput --> AgentProcess
  ExternalAgent -->|VC| Gateway
  AgentProcess -->|token_request| Gateway
  Gateway --> DataServices
  Gateway -.-> AgentProcess
  Gateway --> Monitor
  Issuer --> AgentProcess
  KillSwitch -.-> Gateway
%% SET B2 — Token Replay vs Proof of Possession (Security)
%% Legend: DPoP binds token to agent key.
sequenceDiagram
  autonumber
  participant LegitAgent
  participant Attacker
  participant Gateway

  LegitAgent->>Gateway: token_plus_DPoP
  Gateway-->>LegitAgent: allow

  Attacker->>Gateway: stolen_token_fake_DPoP
  Gateway-->>Attacker: deny_invalid_PoP
%% SET B3 — Confused Deputy Containment (Security)
%% Legend: Child cannot exceed delegated scope.
flowchart LR
  Parent[ParentAgent_caps_A_B_C]
  Attenuator[Attenuator_subset_check]
  Child[ChildAgent_caps_A_B]
  Gateway[ToolGateway]
  ResourceA[ResourceA]
  DeniedC[Denied_C]
  DeniedD[Denied_D]

  Parent -->|delegate_A_B| Attenuator
  Attenuator -->|issue_child_token| Child
  Child -->|action_A| Gateway
  Gateway --> ResourceA
  Child -->|action_C| Gateway
  Gateway -.-> DeniedC
  Child -->|action_D| Gateway
  Gateway -.-> DeniedD
%% SET B4 — Incident Response Flow (Security)
%% Legend: Detect contain investigate.
flowchart TB
  Alert --> Kill
  Kill --> Revoke
  Revoke --> AuditGraph
  AuditGraph --> Evidence

  subgraph Detection
    Alert
  end

  subgraph Containment
    Kill
    Revoke
  end

  subgraph Forensics
    AuditGraph
    Evidence
  end
%% SET C1 — High Level Capability Model (Architecture Communication)
%% Legend: All actions gated by capability token.
flowchart LR
  User --> IdP
  IdP --> Issuer
  Issuer --> Agent
  Agent --> Gateway
  Gateway --> Service
  Gateway --> Audit
%% SET C2 — Authorization Lifecycle (Architecture Communication)
%% Legend: Token governs each action.
sequenceDiagram
  autonumber
  participant User
  participant IdP
  participant Issuer
  participant Agent
  participant Gateway

  User->>IdP: login
  IdP-->>Issuer: identity_context
  Issuer-->>Agent: capability_token
  Agent->>Gateway: action_request
  Gateway-->>Agent: allow_or_deny
%% SET C3 — Cross Organization Trust via DID and VC (Architecture Communication)
%% Legend: Public DID resolution enables verification.
flowchart LR
  IssuerA -->|issue_VC| AgentA
  AgentA -->|present_VC| ServiceB
  ServiceB -.-> DIDRegistry
  ServiceB -->|verify_and_allow| ServiceB
