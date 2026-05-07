#!/usr/bin/env node
/*
 * Helm values.schema.json generator.
 *
 * Reads the typed Zod schemas from `packages/common/src/config/schema.ts`
 * (via the compiled `packages/common/dist/`) and writes a JSON Schema
 * (draft-07, Helm-compatible) for each registered service under
 * `k8s/helm/<service>/values.schema.json`.
 *
 * The generated schemas let Helm validate a `values.yaml` that exposes
 * the service's configuration via an `env:` key, e.g.:
 *
 *   # values.yaml
 *   env:
 *     ISSUER_JWKS_URI: "https://issuer.example.com/.well-known/jwks.json"
 *     PORT: "8080"
 *
 * Two modes:
 *
 *   node scripts/generate-helm-schema.mjs           # (re)write the files
 *   node scripts/generate-helm-schema.mjs --check   # exit 1 on drift
 *
 * The `--check` mode is intended for CI: it regenerates the artefacts in
 * memory and compares them byte-for-byte against the committed copies,
 * failing the build if the Zod schemas and the generated Helm schemas
 * have drifted apart.
 *
 * Prerequisites:
 *   npm run build -w @euno/common   (produces packages/common/dist/)
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(__filename), '..');
const commonDist = path.join(repoRoot, 'euno-platform', 'packages', 'common', 'dist');

// ---------------------------------------------------------------------------
// Argument handling
// ---------------------------------------------------------------------------
const args = process.argv.slice(2);
const CHECK_MODE = args.includes('--check');

if (args.some((a) => a === '--help' || a === '-h')) {
  console.log(`Usage: node scripts/generate-helm-schema.mjs [--check]

  (no flags)   Regenerate k8s/helm/<service>/values.schema.json
  --check      Exit 1 if any generated file differs from the committed copy
`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Load the compiled common package
// ---------------------------------------------------------------------------
if (!existsSync(commonDist)) {
  console.error(
    `ERROR: ${commonDist} not found.\n` +
    'Run `npm run build -w @euno/common` first.'
  );
  process.exit(2);
}

const { EUNO_CONFIG_SCHEMAS, EUNO_SERVICE_NAMES } = await import(
  path.join(commonDist, 'config', 'schema.js')
);

// ---------------------------------------------------------------------------
// Minimal Zod → JSON Schema (draft-07) converter
//
// We only need to handle the small set of Zod primitives actually used
// in schema.ts — z.string, z.number, z.boolean, z.enum, z.literal,
// z.array, z.union, z.optional, z.default, z.describe, z.pipe,
// z.effects (superRefine / transform).  This mirrors the approach used
// in packages/common/src/config/dump-template.ts.
// ---------------------------------------------------------------------------

/** @param {import('zod').ZodTypeAny} zodType */
function zodToJsonSchemaProperty(zodType) {
  const MAX_DEPTH = 8;

  /** @param {import('zod').ZodTypeAny} t @param {number} depth */
  function convert(t, depth) {
    if (depth > MAX_DEPTH) return { type: 'string' };

    const def = t._def;
    if (!def) return { type: 'string' };

    const typeName = def.typeName;

    // Collect description / default before unwrapping.
    const description = def.description ?? undefined;

    switch (typeName) {
      case 'ZodString':
        return { type: 'string', ...(description ? { description } : {}) };

      case 'ZodNumber':
        return { type: 'number', ...(description ? { description } : {}) };

      case 'ZodBoolean':
        return { type: 'boolean', ...(description ? { description } : {}) };

      case 'ZodEnum': {
        const values = def.values;
        return {
          type: 'string',
          enum: values,
          ...(description ? { description } : {}),
        };
      }

      case 'ZodLiteral':
        return {
          type: typeof def.value,
          enum: [def.value],
          ...(description ? { description } : {}),
        };

      case 'ZodUnion': {
        const options = def.options ?? [];
        return {
          oneOf: options.map((o) => convert(o, depth + 1)),
          ...(description ? { description } : {}),
        };
      }

      case 'ZodArray': {
        const items = convert(def.type, depth + 1);
        return {
          type: 'array',
          items,
          ...(description ? { description } : {}),
        };
      }

      case 'ZodOptional':
        // Optional wrapper — unwrap but pass description through
        return addDescription(convert(def.innerType, depth + 1), description);

      case 'ZodNullable':
        return addDescription(convert(def.innerType, depth + 1), description);

      case 'ZodDefault': {
        const inner = convert(def.innerType, depth + 1);
        const defaultValue = def.defaultValue?.();
        return {
          ...inner,
          ...(defaultValue !== undefined ? { default: defaultValue } : {}),
          ...(description ? { description } : {}),
        };
      }

      case 'ZodEffects':
        // transform / superRefine wrappers — unwrap to the inner schema
        return addDescription(convert(def.schema, depth + 1), description);

      case 'ZodPipeline':
        // .pipe(...) — use the input schema (pre-transform).  Numeric coercion
        // (envPositiveInt) and boolean coercion (envBoolean) both look identical
        // at the Zod _def level (ZodOptional → ZodEffects) so we cannot reliably
        // distinguish them without running the transform.  Helm validates string
        // presence; the service schema validates type correctness at boot via Zod.
        return addDescription(convert(def.in, depth + 1), description);

      case 'ZodObject':
        // Nested objects are unusual in env-var schemas but handle gracefully
        return { type: 'object', ...(description ? { description } : {}) };

      case 'ZodAny':
      case 'ZodUnknown':
      default:
        return { type: 'string', ...(description ? { description } : {}) };
    }
  }

  function addDescription(schema, desc) {
    if (!desc) return schema;
    if (schema.description) return schema; // inner already has one
    return { ...schema, description: desc };
  }

  return convert(zodType, 0);
}

// ---------------------------------------------------------------------------
// Build a Helm-compatible values.schema.json from a ZodObject schema
// ---------------------------------------------------------------------------

/** @param {import('zod').ZodObject<any>} schema @param {string} serviceName */
function buildHelmJsonSchema(schema, serviceName) {
  // schema may be wrapped in ZodEffects (superRefine)
  let innerSchema = schema;
  while (innerSchema._def?.typeName === 'ZodEffects') {
    innerSchema = innerSchema._def.schema;
  }

  const shape = innerSchema._def?.shape?.() ?? innerSchema.shape ?? {};

  const envProperties = {};
  const required = [];

  for (const [key, zodType] of Object.entries(shape)) {
    const property = zodToJsonSchemaProperty(zodType);
    envProperties[key] = property;

    // A field is required only if it does NOT accept undefined as input.
    // Using safeParse(undefined) is the canonical way to detect this:
    // - ZodPipeline helpers (envBoolean, envPositiveInt, envEnum, envCsv) all
    //   use optionalString as the input side, so undefined is always accepted
    //   when a default is present.
    // - Plain optionalString fields accept undefined by definition.
    // - A truly required field (e.g. bare z.string()) will fail on undefined.
    const isOptional = zodType.safeParse(undefined).success;

    if (!isOptional) {
      required.push(key);
    }
  }

  return {
    $schema: 'https://json-schema.org/draft-07/schema#',
    title: `${serviceName} Helm values`,
    description:
      `Configuration schema for the \`${serviceName}\` service. ` +
      `Generated from packages/common/src/config/schema.ts — do not edit by hand. ` +
      `Regenerate with \`npm run gen:helm-schema\` from the repository root.`,
    type: 'object',
    properties: {
      env: {
        type: 'object',
        description:
          'Environment variables injected into the service container. ' +
          'Keys map 1-to-1 to the environment variables consumed by the service.',
        properties: envProperties,
        required: required.length > 0 ? required : undefined,
        additionalProperties: false,
      },
    },
    required: ['env'],
  };
}

// ---------------------------------------------------------------------------
// Write or compare
// ---------------------------------------------------------------------------

let drifted = 0;

for (const service of EUNO_SERVICE_NAMES) {
  const schema = EUNO_CONFIG_SCHEMAS[service];
  if (!schema) continue;

  const jsonSchema = buildHelmJsonSchema(schema, service);
  // JSON.stringify natively omits undefined-valued properties; no custom
  // replacer needed.  The `required` array is set to undefined when empty
  // and will be absent from the output automatically.
  const jsonText = JSON.stringify(jsonSchema, null, 2) + '\n';

  const outDir = path.join(repoRoot, 'k8s', 'helm', service);
  const outFile = path.join(outDir, 'values.schema.json');

  if (CHECK_MODE) {
    if (!existsSync(outFile)) {
      console.error(`DRIFT: ${outFile} does not exist (run without --check to generate)`);
      drifted++;
      continue;
    }
    const existing = await readFile(outFile, 'utf8');
    if (existing !== jsonText) {
      console.error(`DRIFT: ${outFile} differs from the schema-derived content`);
      drifted++;
    } else {
      console.log(`OK:    ${outFile}`);
    }
  } else {
    await mkdir(outDir, { recursive: true });
    await writeFile(outFile, jsonText, 'utf8');
    console.log(`Wrote: ${outFile}`);
  }
}

if (CHECK_MODE && drifted > 0) {
  console.error(`\n${drifted} file(s) have drifted. Run \`npm run gen:helm-schema\` to fix.`);
  process.exit(1);
}
