#!/usr/bin/env node
/**
 * Euno CLI - Command-line interface for capability management
 * Provides tools for developers to work with agent capabilities
 */

import { Command } from 'commander';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import axios from 'axios';

const program = new Command();

program
  .name('euno')
  .description('Euno - Capability management CLI for AI agents')
  .version('1.0.0');

/**
 * Initialize a new agent capability manifest
 */
program
  .command('init')
  .description('Initialize a new agent capability manifest')
  .option('-a, --agent <name>', 'Agent name')
  .option('-o, --output <file>', 'Output file', './agent-capability.yaml')
  .action((options) => {
    const agentName = options.agent || 'MyAgent';
    const outputFile = options.output;

    const manifest = {
      agentId: agentName.toLowerCase().replace(/\s+/g, '-'),
      name: agentName,
      version: '1.0.0',
      requiredCapabilities: [
        {
          resource: 'api://service/endpoint',
          actions: ['read'],
          // Conditions are now a typed array (see CapabilityCondition).
          // Leave empty in the scaffold; callers add e.g.
          //   { type: 'timeWindow', notAfter: '2026-01-01T00:00:00Z' }.
          conditions: [],
        },
      ],
      optionalCapabilities: [],
      metadata: {
        description: `Capability manifest for ${agentName}`,
        owner: 'team@example.com',
        tags: [],
      },
    };

    fs.writeFileSync(outputFile, yaml.dump(manifest));
    console.log(`✓ Created capability manifest: ${outputFile}`);
    console.log(`  Agent ID: ${manifest.agentId}`);
    console.log(`  Edit the file to customize capabilities`);
  });

/**
 * Validate a capability manifest
 */
program
  .command('validate')
  .description('Validate an agent capability manifest')
  .argument('<file>', 'Manifest file to validate')
  .action((file) => {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const manifest = yaml.load(content) as Record<string, unknown>;

      // Basic validation
      const required = ['agentId', 'name', 'version', 'requiredCapabilities'];
      const missing = required.filter(field => !manifest[field]);

      if (missing.length > 0) {
        console.error(`✗ Validation failed: missing required fields: ${missing.join(', ')}`);
        process.exit(1);
      }

      console.log(`✓ Manifest is valid`);
      console.log(`  Agent: ${manifest.name} (${manifest.agentId})`);
      console.log(`  Version: ${manifest.version}`);
      const reqCapabilities = manifest.requiredCapabilities;
      console.log(`  Required capabilities: ${Array.isArray(reqCapabilities) ? reqCapabilities.length : 0}`);
    } catch (error) {
      console.error(`✗ Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

/**
 * Request a capability token
 */
program
  .command('request')
  .description('Request a capability token from the issuer')
  .option('-i, --issuer <url>', 'Issuer URL', process.env.EUNO_ISSUER_URL || 'http://localhost:3001')
  .option('-a, --agent <id>', 'Agent ID (required)', '')
  .option('-t, --token <token>', 'Azure AD bearer token (or set AZURE_AD_TOKEN env var)', process.env.AZURE_AD_TOKEN || '')
  .option('-m, --manifest <file>', 'Capability manifest file')
  .option('-r, --resources <resources...>', 'Resource URIs (e.g., api://service/endpoint)')
  .option('--actions <actions...>', 'Actions (e.g., read write)')
  .action(async (options) => {
    // Also accept token from env var directly (options default already handles this,
    // but guard here in case both paths yield an empty string)
    const token: string = options.token;
    if (!token) {
      console.error('✗ Azure AD bearer token is required');
      console.error('  Use --token <token> or set the AZURE_AD_TOKEN environment variable');
      console.error('  Example: euno request --agent my-agent --token $AZURE_AD_TOKEN');
      process.exit(1);
    }

    if (!options.agent) {
      console.error('✗ Agent ID is required (use --agent)');
      process.exit(1);
    }

    console.log(`Requesting capability from ${options.issuer}...`);
    console.log(`  Agent ID: ${options.agent}`);

    try {
      let requestedCapabilities: Array<{resource: string; actions: string[]}> = [];

      // If manifest file provided, load capabilities from it
      if (options.manifest) {
        const content = fs.readFileSync(options.manifest, 'utf8');
        const manifest = yaml.load(content) as Record<string, unknown>;

        if (!Array.isArray(manifest.requiredCapabilities) || manifest.requiredCapabilities.length === 0) {
          console.error('✗ Manifest must contain a non-empty "requiredCapabilities" array');
          process.exit(1);
        }

        const invalid = (manifest.requiredCapabilities as unknown[]).findIndex(
          (cap) =>
            typeof (cap as Record<string, unknown>).resource !== 'string' ||
            !Array.isArray((cap as Record<string, unknown>).actions)
        );
        if (invalid !== -1) {
          console.error(`✗ requiredCapabilities[${invalid}] must have a "resource" string and an "actions" array`);
          process.exit(1);
        }

        requestedCapabilities = manifest.requiredCapabilities as Array<{resource: string; actions: string[]}>;
        console.log(`  Loaded ${requestedCapabilities.length} capabilities from manifest`);
      }
      // Otherwise use command-line resources and actions (both flags required together)
      else if (options.resources && options.actions) {
        requestedCapabilities = options.resources.map((resource: string) => ({
          resource,
          actions: options.actions,
        }));
      } else if (options.resources || options.actions) {
        console.error('✗ --resources and --actions must be provided together');
        console.error('  Example: euno request --agent my-agent --resources api://svc/data --actions read write');
        process.exit(1);
      }
      // Default fallback
      else {
        requestedCapabilities = [{
          resource: 'api://service/endpoint',
          actions: ['read'],
        }];
        console.log('  Using default capabilities (no manifest or resources specified)');
      }

      const response = await axios.post(
        `${options.issuer}/api/v1/issue`,
        {
          agentId: options.agent,
          requestedCapabilities,
        },
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          timeout: 10000,
        }
      );

      console.log('\n✓ Successfully issued capability token:');
      console.log(`  Token ID: ${response.data.tokenId}`);
      console.log(`  Expires: ${new Date(response.data.expiresAt * 1000).toISOString()}`);
      console.log(`  Capabilities: ${response.data.capabilities.length}`);
      console.log('\nToken (save this):');
      console.log(response.data.token);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        console.error('\n✗ Request failed:');
        console.error(`  Status: ${error.response?.status || 'N/A'}`);
        console.error(`  Message: ${error.response?.data?.message || error.message}`);
        if (error.response?.data?.code) {
          console.error(`  Code: ${error.response.data.code}`);
        }
      } else {
        console.error(`✗ Unexpected error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
      process.exit(1);
    }
  });

/**
 * Show current configuration
 */
program
  .command('config')
  .description('Show current CLI configuration')
  .action(() => {
    console.log('Euno CLI Configuration:');
    console.log(`  Default issuer: http://localhost:3001`);
    console.log(`  Default gateway: http://localhost:3002`);
    console.log('');
    console.log('Environment variables:');
    console.log(`  EUNO_ISSUER_URL: ${process.env.EUNO_ISSUER_URL || '(not set)'}`);
    console.log(`  EUNO_GATEWAY_URL: ${process.env.EUNO_GATEWAY_URL || '(not set)'}`);
  });

/**
 * Schema version management commands
 * Check and plan token schema version migrations
 */
const versionCmd = program
  .command('schema-version')
  .description('Manage and migrate capability token schema versions');

versionCmd
  .command('check')
  .description('Check supported schema versions on a capability issuer')
  .option('-i, --issuer <url>', 'Issuer URL', process.env.EUNO_ISSUER_URL || 'http://localhost:3001')
  .action(async (options) => {
    try {
      const url = `${options.issuer}/.well-known/capability-issuer`;
      const response = await axios.get(url, { timeout: 10000 });
      const meta = response.data;

      console.log(`Capability issuer: ${meta.issuer}`);
      console.log(`Current token schema version: ${meta.schemaVersions?.current ?? '(unknown)'}`);
      console.log(`Supported schema versions:    ${(meta.schemaVersions?.supported ?? []).join(', ')}`);
      console.log(`Signing algorithms:           ${(meta.signingAlgorithms ?? []).join(', ')}`);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        console.error(`✗ Could not reach issuer at ${options.issuer}`);
        console.error(`  ${error.message}`);
      } else {
        console.error(`✗ Unexpected error: ${error instanceof Error ? error.message : String(error)}`);
      }
      process.exit(1);
    }
  });

versionCmd
  .command('plan')
  .description('Generate a step-by-step migration plan for a schema version upgrade')
  .argument('<from>', 'Current schema version (e.g. 1.0)')
  .argument('<to>', 'Target schema version (e.g. 1.1)')
  .option('--json', 'Output plan as JSON')
  .action((from: string, to: string, options) => {
    const fromParts = from.split('.').map(Number);
    const toParts = to.split('.').map(Number);
    const fromMajor = fromParts[0] ?? NaN;
    const fromMinor = fromParts[1] ?? NaN;
    const toMajor = toParts[0] ?? NaN;
    const toMinor = toParts[1] ?? NaN;

    if (isNaN(fromMajor) || isNaN(fromMinor) || isNaN(toMajor) || isNaN(toMinor)) {
      console.error('✗ Versions must be in MAJOR.MINOR format (e.g. 1.0, 1.1, 2.0)');
      process.exit(1);
    }

    const isMajor = toMajor > fromMajor;
    const isDowngrade = toMajor < fromMajor || (toMajor === fromMajor && toMinor < fromMinor);

    if (isDowngrade) {
      console.error('✗ Downgrade migrations are not supported. Downgrading past a schema change will reject all tokens with the new shape.');
      process.exit(1);
    }

    const plan = {
      from,
      to,
      type: isMajor ? 'major' : 'minor',
      steps: isMajor
        ? [
            { phase: 'Preparation (Week 1–4)', action: `Add "${to}" to SUPPORTED_SCHEMA_VERSIONS in gateway` },
            { phase: 'Preparation (Week 1–4)', action: 'Implement version-specific parsing/validation logic for new schema shape' },
            { phase: 'Preparation (Week 1–4)', action: 'Deploy gateway updates and verify 100% rollout before proceeding' },
            { phase: 'Transition (Week 5–8)', action: `Update CAPABILITY_TOKEN_SCHEMA_VERSION to "${to}" in issuer` },
            { phase: 'Transition (Week 5–8)', action: 'Deploy issuer updates; both versions coexist during token TTL window' },
            { phase: 'Validation (Week 9–12)', action: `Monitor token version distribution; ensure no "${from}" tokens remain (check TTL)` },
            { phase: 'Deprecation (Week 13+)', action: `Remove "${from}" from SUPPORTED_SCHEMA_VERSIONS in gateway` },
            { phase: 'Deprecation (Week 13+)', action: 'Deploy gateway updates and update documentation' },
          ]
        : [
            { phase: 'Step 1', action: `Add "${to}" to SUPPORTED_SCHEMA_VERSIONS in gateway (packages/common/src/types.ts)` },
            { phase: 'Step 1', action: 'Deploy gateway updates and verify rollout' },
            { phase: 'Step 2', action: `Update CAPABILITY_TOKEN_SCHEMA_VERSION to "${to}" in issuer (packages/common/src/types.ts)` },
            { phase: 'Step 2', action: 'Deploy issuer updates; monitor token version distribution' },
            { phase: 'Step 3 (optional)', action: `After migration window, remove "${from}" from SUPPORTED_SCHEMA_VERSIONS` },
          ],
      warnings: isMajor
        ? [
            'NEVER deploy issuer before all gateways are updated',
            'Old gateways will reject tokens with the new major version',
            `Cross-version delegation is blocked: cannot attenuate a "${from}" token into a "${to}" token`,
          ]
        : [
            'NEVER deploy issuer before all gateways are updated',
            `Gateways only accept versions explicitly listed in SUPPORTED_SCHEMA_VERSIONS — an unupdated gateway will reject "${to}" tokens`,
          ],
    };

    if (options.json) {
      console.log(JSON.stringify(plan, null, 2));
    } else {
      console.log(`\nMigration plan: ${from} → ${to} (${plan.type} version bump)\n`);
      let lastPhase = '';
      for (const step of plan.steps) {
        if (step.phase !== lastPhase) {
          console.log(`\n  ${step.phase}:`);
          lastPhase = step.phase;
        }
        console.log(`    • ${step.action}`);
      }
      console.log('\n  ⚠  Warnings:');
      for (const w of plan.warnings) {
        console.log(`    • ${w}`);
      }
      console.log('');
    }
  });

versionCmd
  .command('validate-token')
  .description('Decode and validate the schema version of a capability token')
  .argument('<token>', 'JWT capability token to inspect')
  .action((token: string) => {
    try {
      // Decode without verification (inspection only)
      const parts = token.split('.');
      if (parts.length !== 3) {
        console.error('✗ Not a valid JWT (expected 3 parts separated by ".")');
        process.exit(1);
      }
      const payloadPart = parts[1];
      if (!payloadPart) {
        console.error('✗ Not a valid JWT (empty payload segment)');
        process.exit(1);
      }
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
      const schemaVersion: unknown = payload.schemaVersion;

      if (!schemaVersion) {
        console.error('✗ Token is missing the required schemaVersion field');
        process.exit(1);
      }
      if (typeof schemaVersion !== 'string') {
        console.error(`✗ schemaVersion must be a string, got: ${typeof schemaVersion}`);
        process.exit(1);
      }

      console.log(`Token schema version: ${schemaVersion}`);
      console.log(`Issuer:  ${payload.iss ?? '(none)'}`);
      console.log(`Subject: ${payload.sub ?? '(none)'}`);
      console.log(`Expires: ${payload.exp ? new Date(payload.exp * 1000).toISOString() : '(none)'}`);
    } catch (error) {
      console.error(`✗ Failed to decode token: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program.parse(process.argv);

// Show help if no command specified
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
