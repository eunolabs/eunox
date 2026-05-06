/**
 * Issuance profile definitions for the perf harness.
 *
 * A profile is a named combination of:
 *
 *   1. A **KMS profile** — the latency budget for the primary signing
 *      operation (models the network RTT to a cloud KMS or the latency
 *      of a software key for the baseline).
 *
 *   2. Optional component latencies — cosigner, side-credential broker,
 *      posture emitter, and transparency-log witness.
 *
 * ### Latency sources
 *
 * All latency values are **p50 estimates for same-region calls** sourced
 * from cloud-provider SLA documentation and community benchmarks:
 *
 * | Provider / Component          | p50 latency |  p95 latency | Source |
 * |-------------------------------|-------------|--------------|--------|
 * | Azure Key Vault (sign)        | 40 ms       | ~100 ms      | Azure docs §Perf; community |
 * | AWS KMS (sign)                | 25 ms       | ~80 ms       | AWS KMS SLA; community |
 * | GCP Cloud KMS (sign)          | 30 ms       | ~90 ms       | GCP KMS docs |
 * | Software cosigner (Ed25519)   | 2 ms        | ~4 ms (2×p50) | measured |
 * | Side-credential broker (stub) | 8 ms        | ~16 ms (2×p50)| measured |
 * | Posture emitter (async)       | N/A†        | N/A†         | fire-and-forget |
 * | Transparency log (in-proc)    | 3 ms        | ~6 ms (2×p50) | measured |
 *
 * † Posture emission is fire-and-forget on the critical path; the delay
 *   exists to stress the event loop under load but does not appear in
 *   the issuance p99.
 *
 * ### SLO budgets
 *
 * The p99 budget for each profile is declared in `slo.ts` — that file is
 * the single source of truth. The derivation formula is:
 *
 *   p99_budget = KMS_P95_LATENCY + sum(optional_P95_latencies) + NODE_OVERHEAD_MS
 *
 * where `NODE_OVERHEAD_MS` = 50 ms (the baseline `issuer-issue` p99).
 *
 * The README claims "Token issuance < 500 ms (p95)". The `full` profiles
 * target exactly that ceiling so an automated test can defend the claim:
 * if any future change pushes the full-stack scenario past 500 ms, CI
 * fails before the claim becomes a lie.
 */

// ---------------------------------------------------------------------------
// KMS profiles
// ---------------------------------------------------------------------------

export interface KmsProfile {
  /** Canonical name, used as the profile tag in scenario names. */
  name: 'baseline' | 'azure' | 'aws' | 'gcp';
  /** Human-readable description shown in the report. */
  description: string;
  /**
   * Simulated latency injected before every `sign()` call (ms).
   * Set to 0 for the software-key baseline.
   */
  signLatencyMs: number;
  /**
   * P95 KMS latency used to derive `issuanceP99BudgetMs` for scenarios
   * that layer optionals on top of this KMS profile.
   */
  kmsP95Ms: number;
}

export const KMS_PROFILES: Record<KmsProfile['name'], KmsProfile> = {
  baseline: {
    name: 'baseline',
    description:
      'Software RSA-2048 key (no external KMS). ' +
      'Establishes the Node.js processing overhead floor.',
    signLatencyMs: 0,
    kmsP95Ms: 0,
  },
  azure: {
    name: 'azure',
    description:
      'Azure Key Vault (simulated). ' +
      'Models a typical same-region ECDSA or RSA-2048 HSM sign operation.',
    signLatencyMs: 40,
    kmsP95Ms: 100,
  },
  aws: {
    name: 'aws',
    description:
      'AWS KMS (simulated). ' +
      'Models a same-region asymmetric-sign operation.',
    signLatencyMs: 25,
    kmsP95Ms: 80,
  },
  gcp: {
    name: 'gcp',
    description:
      'GCP Cloud KMS (simulated). ' +
      'Models a same-region asymmetric-sign operation.',
    signLatencyMs: 30,
    kmsP95Ms: 90,
  },
} as const;

// ---------------------------------------------------------------------------
// Optional-component latencies
// ---------------------------------------------------------------------------

/**
 * Latency contributed by each optional issuance component (ms, p50
 * estimates for same-datacenter deployments).
 */
export const OPTIONAL_LATENCIES_MS = {
  /** Software Ed25519 cosigner — in-process, no network. */
  cosigner: 2,
  /** Remote cosigner / HSM-backed co-signing service (same-datacenter). */
  cosignerRemote: 20,
  /**
   * In-process side-credential broker stub (models the
   * `InProcessSideCredentialBroker` path, which delegates to
   * `StorageGrantService` and `DbTokenService`).
   */
  sideCredentialsBroker: 8,
  /**
   * Fire-and-forget posture emitter (HTTP PUT to a posture surface,
   * modeled at typical same-datacenter latency). Does NOT appear in
   * the issuance p99 because the issuer never awaits it.
   */
  postureEmitter: 15,
  /**
   * In-process transparency-log witness (same-process, no network).
   * Appears on the critical path because the SCT is embedded in the token.
   */
  transparencyLog: 3,
} as const;

// ---------------------------------------------------------------------------
// Issuance profiles
// ---------------------------------------------------------------------------

/**
 * Optional-component configuration for an issuance profile. Each field
 * controls whether the corresponding stub is wired into the issuer service
 * and what latency the stub injects.
 */
export interface IssuanceProfileOptions {
  /** Enable a software cosigner with configurable latency. */
  cosign?: { latencyMs: number };
  /**
   * Enable the side-credential broker stub with configurable latency.
   * Both storage grants and DB credentials are enabled.
   */
  sideCreds?: { latencyMs: number };
  /**
   * Wire in a posture emitter stub. Fire-and-forget — does not affect p99.
   */
  posture?: { latencyMs: number };
  /**
   * Enable a transparency-log witness stub with configurable latency.
   * The SCT is embedded in the token, so this latency is on the critical
   * path.
   */
  witness?: { latencyMs: number };
}

/**
 * A fully-specified issuance profile: KMS + optional components. The
 * harness builds one `CapabilityIssuerService` per profile; each scenario
 * targets the appropriate service via `issuer:<profile.tag>`.
 */
export interface IssuanceProfile {
  /**
   * Canonical tag. Used as the suffix in scenario names
   * (`issuer-issue:<tag>`) and as the routing key in the harness's
   * `profiledIssuerUrls` map.
   */
  tag: string;
  /** Human-readable one-liner shown in `--list` and in the report. */
  description: string;
  /** The KMS profile that governs the signing operation. */
  kms: KmsProfile;
  /** Optional-component wiring. */
  optionals: IssuanceProfileOptions;
}

// ---------------------------------------------------------------------------
// Concrete profiles
// ---------------------------------------------------------------------------

/**
 * All profiled issuance scenarios. The harness starts one issuer server
 * per entry; the corresponding scenarios are named
 * `issuer-issue:<profile.tag>`.
 *
 * Layout:
 *  - `{cloud}`:             cloud KMS only, no optionals
 *  - `{cloud}+cosign`:      cloud KMS + software cosigner
 *  - `{cloud}+sidecreds`:   cloud KMS + side-credential broker
 *  - `{cloud}+full`:        cloud KMS + cosigner + side creds + posture + witness
 *
 * The baseline (software signer, no optionals) is the existing
 * `issuer-issue` scenario in `slo.ts` — not duplicated here.
 */
export const ISSUANCE_PROFILES: readonly IssuanceProfile[] = [
  // ── Azure Key Vault ─────────────────────────────────────────────────────
  {
    tag: 'azure',
    description:
      'Azure Key Vault (simulated p50 latency): primary signing only.',
    kms: KMS_PROFILES.azure,
    optionals: {},
  },
  {
    tag: 'azure+cosign',
    description:
      'Azure Key Vault + software Ed25519 cosigner.',
    kms: KMS_PROFILES.azure,
    optionals: { cosign: { latencyMs: OPTIONAL_LATENCIES_MS.cosigner } },
  },
  {
    tag: 'azure+sidecreds',
    description:
      'Azure Key Vault + in-process side-credential broker (storage grant + DB token).',
    kms: KMS_PROFILES.azure,
    optionals: {
      sideCreds: { latencyMs: OPTIONAL_LATENCIES_MS.sideCredentialsBroker },
    },
  },
  {
    tag: 'azure+full',
    description:
      'Azure Key Vault + cosigner + side creds + posture emitter + transparency log. ' +
      'Exercises the maximum stacked-optionals overhead for the Azure profile. ' +
      'Budget ≤ 500 ms defends the README "Token issuance < 500 ms (p95)" claim.',
    kms: KMS_PROFILES.azure,
    optionals: {
      cosign: { latencyMs: OPTIONAL_LATENCIES_MS.cosigner },
      sideCreds: { latencyMs: OPTIONAL_LATENCIES_MS.sideCredentialsBroker },
      posture: { latencyMs: OPTIONAL_LATENCIES_MS.postureEmitter },
      witness: { latencyMs: OPTIONAL_LATENCIES_MS.transparencyLog },
    },
  },
  // ── AWS KMS ─────────────────────────────────────────────────────────────
  {
    tag: 'aws',
    description:
      'AWS KMS (simulated p50 latency): primary signing only.',
    kms: KMS_PROFILES.aws,
    optionals: {},
  },
  {
    tag: 'aws+cosign',
    description:
      'AWS KMS + software Ed25519 cosigner.',
    kms: KMS_PROFILES.aws,
    optionals: { cosign: { latencyMs: OPTIONAL_LATENCIES_MS.cosigner } },
  },
  {
    tag: 'aws+sidecreds',
    description:
      'AWS KMS + in-process side-credential broker.',
    kms: KMS_PROFILES.aws,
    optionals: {
      sideCreds: { latencyMs: OPTIONAL_LATENCIES_MS.sideCredentialsBroker },
    },
  },
  {
    tag: 'aws+full',
    description:
      'AWS KMS + cosigner + side creds + posture emitter + transparency log. ' +
      'Budget ≤ 500 ms defends the README "Token issuance < 500 ms (p95)" claim.',
    kms: KMS_PROFILES.aws,
    optionals: {
      cosign: { latencyMs: OPTIONAL_LATENCIES_MS.cosigner },
      sideCreds: { latencyMs: OPTIONAL_LATENCIES_MS.sideCredentialsBroker },
      posture: { latencyMs: OPTIONAL_LATENCIES_MS.postureEmitter },
      witness: { latencyMs: OPTIONAL_LATENCIES_MS.transparencyLog },
    },
  },
  // ── GCP Cloud KMS ────────────────────────────────────────────────────────
  {
    tag: 'gcp',
    description:
      'GCP Cloud KMS (simulated p50 latency): primary signing only.',
    kms: KMS_PROFILES.gcp,
    optionals: {},
  },
  {
    tag: 'gcp+cosign',
    description:
      'GCP Cloud KMS + software Ed25519 cosigner.',
    kms: KMS_PROFILES.gcp,
    optionals: { cosign: { latencyMs: OPTIONAL_LATENCIES_MS.cosigner } },
  },
  {
    tag: 'gcp+sidecreds',
    description:
      'GCP Cloud KMS + in-process side-credential broker.',
    kms: KMS_PROFILES.gcp,
    optionals: {
      sideCreds: { latencyMs: OPTIONAL_LATENCIES_MS.sideCredentialsBroker },
    },
  },
  {
    tag: 'gcp+full',
    description:
      'GCP Cloud KMS + cosigner + side creds + posture emitter + transparency log. ' +
      'Budget ≤ 500 ms defends the README "Token issuance < 500 ms (p95)" claim.',
    kms: KMS_PROFILES.gcp,
    optionals: {
      cosign: { latencyMs: OPTIONAL_LATENCIES_MS.cosigner },
      sideCreds: { latencyMs: OPTIONAL_LATENCIES_MS.sideCredentialsBroker },
      posture: { latencyMs: OPTIONAL_LATENCIES_MS.postureEmitter },
      witness: { latencyMs: OPTIONAL_LATENCIES_MS.transparencyLog },
    },
  },
] as const;

/** Type-safe lookup: profile tag → profile definition. */
export const ISSUANCE_PROFILE_MAP: ReadonlyMap<string, IssuanceProfile> =
  new Map(ISSUANCE_PROFILES.map((p) => [p.tag, p]));
