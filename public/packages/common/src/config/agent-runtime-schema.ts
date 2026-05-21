import { z } from 'zod';
import { optionalString, envPositiveInt, envPort, NODE_ENV } from './base-schema';

// ---------------------------------------------------------------------------
// Agent Runtime schema — `agent-runtime`
// ---------------------------------------------------------------------------

export const AgentRuntimeConfigSchema = z
  .object({
    NODE_ENV,
    PORT: envPort({
      default: 3003,
      description: 'TCP port the agent-runtime health check HTTP server binds to.',
    }),

    // Agent identity
    AGENT_ID: z
      .string()
      .min(1)
      .describe(
        'Unique identifier for this agent. Included in capability-token requests as the ' +
        '`agentId` claim. Required.',
      ),
    GATEWAY_URL: z
      .string()
      .url()
      .describe(
        'URL of the tool-gateway this agent connects to. Required. ' +
        'Example: https://gateway.example.com',
      ),
    ISSUER_URL: z
      .string()
      .url()
      .describe(
        'URL of the capability-issuer this agent authenticates against. Required. ' +
        'Example: https://issuer.example.com',
      ),
    AUTH_TOKEN: optionalString.describe(
      'Bootstrap credential presented to the issuer to obtain the first capability token. ' +
      'This is the agent\'s proof of identity (e.g. an OIDC access token or API key). ' +
      'Required unless AUTH_TOKEN_FILE is set.',
    ),

    AUTH_TOKEN_FILE: z
      .string()
      .transform((v) => (v === '' ? undefined : v.trim()))
      .optional()
      .refine(
        (v) => v === undefined || v.length > 0,
        'AUTH_TOKEN_FILE must be a non-blank file path.',
      )
      .describe(
        'Path to a file containing the authentication token. When set, the runtime reads ' +
        'the token from this file on every capability-issuance request so the token is never ' +
        'retained in memory between refreshes. Use with Kubernetes projected service-account ' +
        'tokens (Azure Workload Identity, SPIRE) mounted at e.g. ' +
        '/var/run/service-account/token. Takes precedence over AUTH_TOKEN when both are set.',
      ),

    // Token refresh
    TOKEN_REFRESH_INTERVAL: envPositiveInt({
      default: 600,
      description:
        'How often (seconds) the agent proactively refreshes its capability token before it ' +
        'expires. Default 600 (10 minutes). Set below DEFAULT_TOKEN_TTL on the issuer.',
    }),
  })
  .refine(
    (cfg) => !!(cfg.AUTH_TOKEN ?? cfg.AUTH_TOKEN_FILE),
    {
      message: 'Either AUTH_TOKEN or AUTH_TOKEN_FILE must be set.',
      path: ['AUTH_TOKEN'],
    },
  );

export type AgentRuntimeConfig = z.infer<typeof AgentRuntimeConfigSchema>;
