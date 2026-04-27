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
          conditions: {},
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
  .option('-t, --token <token>', 'Azure AD bearer token (required)', '')
  .option('-m, --manifest <file>', 'Capability manifest file')
  .option('-r, --resources <resources...>', 'Resource URIs (e.g., api://service/endpoint)')
  .option('--actions <actions...>', 'Actions (e.g., read write)')
  .action(async (options) => {
    if (!options.token) {
      console.error('✗ Azure AD bearer token is required (use --token or AZURE_AD_TOKEN env var)');
      console.error('Example: euno request --agent my-agent --token $AZURE_AD_TOKEN');
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
        requestedCapabilities = manifest.requiredCapabilities as Array<{resource: string; actions: string[]}>;
        console.log(`  Loaded ${requestedCapabilities.length} capabilities from manifest`);
      }
      // Otherwise use command-line resources and actions
      else if (options.resources && options.actions) {
        requestedCapabilities = options.resources.map((resource: string) => ({
          resource,
          actions: options.actions,
        }));
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
            'Authorization': `Bearer ${options.token}`,
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

program.parse(process.argv);

// Show help if no command specified
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
