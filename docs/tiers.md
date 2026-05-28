# eunox Tiers

> **Status:** Current as of the Go re-implementation.
> This document is the authoritative reference for the eunox tiers and
> the feature boundaries between them.
>
> **Related documents:**
>
> - [`docs/self-host.md`](./self-host.md) — BYO-GW guide (what self-hosting means in practice)
> - [`docs/upgrade-to-hosted.md`](./upgrade-to-hosted.md) — migrate from local to hosted enforcement

---

## 1. Tiers at a glance

|                                | Self-Host  | Cloud Free | Cloud Team | Cloud Enterprise |
| ------------------------------ | :--------: | :--------: | :--------: | :--------------: |
| **License**                    |  BSL 1.1   |     —      |     —      |        —         |
| **Infrastructure**             |    BYO     |  Managed   |  Managed   |     Managed      |
| **Price**                      |    Free    |    Free    | Contact us |    Contact us    |
| **Agents**                     | Unlimited  |  Up to 5   | Unlimited  |    Unlimited     |
| **Enforcement events / month** | Unlimited  |   50 000   | Unlimited  |    Unlimited     |
| **Audit retention**            | You manage |   7 days   |  90 days   |   Configurable   |
| **SLA**                        |    None    |    None    |   99.9 %   |     99.99 %      |
| **Support**                    | Community  | Community  |   Email    |    Dedicated     |

---

## 2. Feature matrix

The table below maps every platform feature to the tier that gates it.

| Feature                                                      |  Self-Host (BSL)  |   Cloud Free    |    Cloud Team    | Cloud Enterprise |
| ------------------------------------------------------------ | :---------------: | :-------------: | :--------------: | :--------------: |
| **Core enforcement**                                         |                   |                 |                  |
| Local enforcement (in-process PDP)                           |        ✅         |       ✅        |        ✅        |        ✅        |
| stdio + HTTP proxy transports                                |        ✅         |       ✅        |        ✅        |        ✅        |
| All condition types                                          |        ✅         |       ✅        |        ✅        |        ✅        |
| Local HMAC audit log                                         |        ✅         |       ✅        |        ✅        |        ✅        |
| `eunox-mcp validate-token` / `stats`                         |        ✅         |       ✅        |        ✅        |        ✅        |
| **Hosted gateway**                                           |                   |                 |                  |
| Remote enforcer mode (`enforcer: url`)                       |        ✅         |       ✅        |        ✅        |        ✅        |
| KMS-backed audit signer                                      |   ✅ (BYO KMS)    |       ✅        |        ✅        |        ✅        |
| Redis call-counter store                                     |  ✅ (BYO Redis)   |       ✅        |        ✅        |        ✅        |
| Redis kill-switch manager                                    |  ✅ (BYO Redis)   |       ✅        |        ✅        |        ✅        |
| Postgres audit ledger                                        | ✅ (BYO Postgres) |       ✅        |        ✅        |        ✅        |
| Audit query API                                              |        ✅         | 7-day retention | 90-day retention |   Configurable   |
| Kill-switch admin API                                        |        ✅         | Session-scoped  |        ✅        |        ✅        |
| API-key minter façade (`sk-…` → JWT)                         |         —         |       ✅        |        ✅        |        ✅        |
| `eunox-mcp upgrade-to-hosted` CLI                            |         —         |       ✅        |        ✅        |        ✅        |
| **Identity**                                                 |                   |                 |                  |                  |
| SSO via OIDC (Entra ID, Cognito, GCP)                        |   ✅ (BYO IdP)    |        —        |        ✅        |        ✅        |
| DID-based agent identity (did:web, did:key)                  |        ✅         |       ✅        |        ✅        |        ✅        |
| **Enterprise**                                               |                   |                 |                  |                  |
| Evidence export (signed OCSF, `GET /api/v1/audit/export`)    |        ✅         |        —        |        —         |        ✅        |
| On-prem / BYO HSM signing key                                |        ✅         |        —        |        —         |        ✅        |
| SOC2 attestation documentation                               |        ✅         |        —        |        —         |        ✅        |
| Cross-chain audit anchor                                     |        ✅         |        —        |        —         |        ✅        |
| Partner DID federation (two-eyes DID registry)               |        ✅         |        —        |        —         |        ✅        |
| SCIM 2.0 agent provisioning (`/scim/v2/`)                    |        ✅         |        —        |        —         |        ✅        |
| DB credential issuance (db-token-service)                    |        ✅         |        —        |        —         |        ✅        |
| Storage-grant issuance (storage-grant-service)               |        ✅         |        —        |        —         |        ✅        |
| AGT in-process guard (`agentruntime.New()`)                  |        ✅         |        —        |        —         |        ✅        |
| Discovery endpoint v1.0.0 (`/.well-known/capability-issuer`) |        ✅         |        —        |        —         |        ✅        |
| Helm chart + air-gap bundle (`k8s/helm/`)                    |        ✅         |        —        |        —         |        ✅        |
| Posture emitter + CSPM plugin delivery                       |        ✅         |        —        |        —         |        ✅        |
| Redis HA enforcement (multi-node Redis required)             |        ✅         |        —        |        —         |        ✅        |

---

## 3. Tier descriptions

### Self-Host — BSL 1.1

The self-hosted option ships the full gateway stack (capability issuer, tool
gateway, API-key minter, posture emitter, and all enterprise services) as BSL 1.1
Docker images. Self-hosters manage their own Redis, Postgres, and KMS.

**License:** BSL 1.1 (non-competing use; converts to Apache-2.0 four years
after each release). Review the [LICENSE](../LICENSE) before deploying in a
competing product.

**Key difference from Cloud:** No managed minter façade. Self-hosters must issue
JWT capability tokens directly via `cmd/issuer` (the capability-issuer service)
or a compatible issuer. The gateway verifier path is identical — the
cryptographic-token invariant is fully preserved.

See [`docs/self-host.md`](./self-host.md) for deployment instructions.

---

### Cloud Free

Fully managed eunox Cloud hosted on eunox infrastructure. Suitable for
proof-of-concept work and small teams evaluating the platform.

**Limits:**

- Up to 5 concurrent agents
- 50 000 enforcement events per month
- 7-day audit retention

**Getting started:** Sign up at [eunox.dev](https://eunox.dev) and run:

```bash
eunox-mcp upgrade-to-hosted \
  --gateway-url https://gateway.eunox.dev \
  --api-key sk-<your-api-key>
```

---

### Cloud Team

Designed for engineering teams with shared policy management, OIDC SSO, and
90-day audit retention.

**Includes everything in Cloud Free, plus:**

- Unlimited agents and enforcement events
- SSO via OIDC (Entra ID, Cognito, GCP Workforce)
- 90-day audit retention
- Email support with 99.9 % uptime SLA

Contact us at [hello@eunox.dev](mailto:hello@eunox.dev) for pricing.

---

### Cloud Enterprise

For organizations requiring compliance evidence, air-gap deployments,
SOC2 documentation, and dedicated SLA.

**Includes everything in Cloud Team, plus:**

- Configurable audit retention
- Evidence export (signed OCSF audit bundles, `GET /api/v1/audit/export`)
- SOC2 attestation documentation
- Cross-chain audit anchor
- Partner DID federation
- SCIM 2.0 agent provisioning
- DB credential and storage-grant issuance
- Helm chart + air-gap image bundle
- Posture emitter with CSPM plugin delivery (AWS Security Hub, GCP SCC, Microsoft Defender)
- Dedicated support with 99.99 % uptime SLA

Contact us at [hello@eunox.dev](mailto:hello@eunox.dev) for pricing.

---

## 4. Metering

All metering is handled server-side in the gateway. The following counters are
exposed via Prometheus and the admin API:

| Metric                                              | Description                                     |
| --------------------------------------------------- | ----------------------------------------------- |
| `eunox_enforcement_requests_total{tenant,decision}` | Enforcement decisions (allow / deny) per tenant |
| `eunox_audit_records_total{tenant}`                 | Audit records written to the ledger             |
| `eunox_killswitch_invocations_total{tenant}`        | Kill-switch activations                         |
| `eunox_minter_mint_total{tenant,result}`            | API-key minter invocations                      |
| `eunox_posture_enqueued_total{event_type}`          | Posture events enqueued for CSPM delivery       |

Monthly enforcement-event counts are computed from
`eunox_enforcement_requests_total` and reset on the billing period boundary.
Self-hosters have access to the same metrics — retention and alerting are
entirely under their control.

---

## 5. Billing integration

For Cloud tiers, billing is metered on enforcement events and audit-record
retention days. Billing integration itself operates independently of the
enforcement path — a billing failure never causes enforcement to fail-open.

Self-hosters are not subject to metering or billing by eunox.

---

## 6. Upgrading between tiers

- **Self-Host → Cloud:** Contact us. Your existing YAML policy files and JWT
  issuance configuration are portable; data migration scripts are provided.
- **Cloud Free → Cloud Team / Enterprise:** Upgrade via the eunox Cloud console.
  All audit records are preserved.

---

## 7. License and open-source commitment

| Component                                             | License                         |
| ----------------------------------------------------- | ------------------------------- |
| All server-side services (gateway, issuer, minter, …) | BSL 1.1                         |
| BSL → Apache-2.0 conversion                           | 4 years after each release date |

The BSL conversion guarantee means every version of the self-host bundle
eventually becomes fully open-source. See the [LICENSE](../LICENSE) for the
exact terms.
