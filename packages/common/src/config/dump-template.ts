/**
 * Generate `.env.example`-style template text from a Zod
 * `EunoConfig` schema.  See R-5 in
 * `docs/IMPROVEMENTS_AND_REFACTORING.md`: the existing per-service
 * `.env.example` and `.env.template` duplicates are eliminated; the
 * single source of truth is the schema, and `euno config dump-template
 * --service <name>` regenerates the file.
 */

import {
  ZodObject,
  ZodOptional,
  ZodEffects,
  ZodPipeline,
  ZodTypeAny,
  ZodEnum,
  ZodLiteral,
  ZodUnion,
  ZodNumber,
  ZodBoolean,
  ZodString,
} from 'zod';
import {
  EUNO_CONFIG_SCHEMAS,
  EunoServiceName,
  EUNO_SERVICE_NAMES,
} from './schema';

interface FieldSummary {
  /** Env-var name. */
  name: string;
  /** `.describe(...)` text from the schema. */
  description: string;
  /** Default value as it would appear in a `.env` file, if any. */
  defaultLiteral: string | undefined;
  /** True when the field has no default and is fully optional. */
  optional: boolean;
  /**
   * True when the field individually parses as optional but is required
   * by a `superRefine` cross-field rule under the schema's defaults
   * (e.g. `AZURE_KEYVAULT_URL` when `SIGNING_PROVIDER` defaults to
   * `azure-keyvault`).  Such fields are emitted uncommented with a
   * placeholder so a copied template fails closed at boot rather than
   * appearing to be skip-able.
   */
  conditionallyRequired: boolean;
}

/**
 * Strip the wrapper layers we use in {@link ./schema.ts} so we can get
 * back to the *operator-facing* type of each field (string, enum,
 * number, boolean, csv).  This is intentionally narrow — it only knows
 * about the small set of helpers used in `schema.ts`, not the full
 * Zod surface.
 */
/**
 * Maximum number of wrapper layers we'll peel off before giving up.
 * `optionalString.pipe(...).describe(...)` produces 3-4 layers in
 * practice; the limit is intentionally generous so future helper
 * additions don't quietly silently bottom out.
 */
const MAX_UNWRAP_DEPTH = 16;

function unwrap(type: ZodTypeAny): ZodTypeAny {
  let current: ZodTypeAny = type;
  for (let i = 0; i < MAX_UNWRAP_DEPTH && current; i += 1) {
    if (current instanceof ZodOptional) {
      current = current.unwrap();
      continue;
    }
    if (current instanceof ZodEffects) {
      current = current._def.schema;
      continue;
    }
    if (current instanceof ZodPipeline) {
      // Prefer the *output* of the pipeline since that's the type the
      // operator effectively writes (e.g. an enum's allowed values).
      current = current._def.out;
      continue;
    }
    break;
  }
  return current;
}

function inferOperatorHint(type: ZodTypeAny): string {
  const inner = unwrap(type);
  if (inner instanceof ZodEnum) {
    return inner.options.join(' | ');
  }
  if (inner instanceof ZodNumber) {
    return '<integer>';
  }
  if (inner instanceof ZodBoolean) {
    return 'true | false';
  }
  if (inner instanceof ZodString) {
    // Emit a valid placeholder URL so the generated template passes the
    // "parses cleanly back through loadConfig" contract even for .url()
    // fields (which reject the generic '<value>' placeholder).
    const hasUrlCheck = inner._def.checks.some(
      (c: { kind: string }) => c.kind === 'url',
    );
    if (hasUrlCheck) return 'https://example.com';
  }
  if (inner instanceof ZodUnion) {
    const opts = inner._def.options as ZodTypeAny[];
    const literals = opts
      .map((o) => (o instanceof ZodLiteral ? String(o.value) : null))
      .filter((v): v is string => v !== null);
    if (literals.length === opts.length && literals.length > 0) {
      return literals.join(' | ');
    }
  }
  return '<value>';
}

function summariseField(
  name: string,
  type: ZodTypeAny,
  conditionallyRequiredFields: ReadonlySet<string>,
): FieldSummary {
  // Defaults live on the inner pipeline transform we built in
  // `schema.ts` via `transform((v) => v ?? DEFAULT)`.  Rather than
  // peeking at private Zod internals, run the schema against the
  // unset case and capture whatever value comes back.
  let defaultValue: unknown;
  let isOptional = true;
  try {
    const probe = type.safeParse(undefined);
    if (probe.success) {
      defaultValue = probe.data;
      isOptional = defaultValue === undefined;
    } else {
      // Required field — `safeParse(undefined)` failed, so there's no
      // default and the operator must set it.
      isOptional = false;
    }
  } catch {
    // Defensive: if Zod throws for any reason, treat as optional with
    // no default and fall back to the type-derived hint below.
    isOptional = true;
  }

  let defaultLiteral: string | undefined;
  if (defaultValue !== undefined) {
    if (Array.isArray(defaultValue)) {
      defaultLiteral = defaultValue.join(',');
    } else if (typeof defaultValue === 'boolean' || typeof defaultValue === 'number') {
      defaultLiteral = String(defaultValue);
    } else if (typeof defaultValue === 'string') {
      defaultLiteral = defaultValue;
    }
  }

  const description =
    (type.description && type.description.trim()) || '(no description)';

  return {
    name,
    description,
    defaultLiteral,
    optional: isOptional,
    conditionallyRequired: conditionallyRequiredFields.has(name),
  };
}

/**
 * Wrap a long description into ≤ 78-char comment lines, prefixed with
 * `# `.  This keeps the generated `.env.example` readable in plain
 * editors and matches the style of the existing hand-curated files.
 */
function wrapAsComment(text: string, maxLen = 78): string[] {
  const lines: string[] = [];
  const paragraphs = text.split(/\n+/).map((p) => p.trim()).filter(Boolean);
  for (const para of paragraphs) {
    const words = para.split(/\s+/);
    let line = '#';
    for (const word of words) {
      if (line.length + 1 + word.length > maxLen && line !== '#') {
        lines.push(line);
        line = '#';
      }
      line += ` ${word}`;
    }
    if (line !== '#') lines.push(line);
  }
  return lines;
}

/**
 * Render a single `.env.example` block for one field.  Required
 * fields (whether unconditionally or only under the schema's defaults
 * via `superRefine`) are emitted uncommented with a placeholder value;
 * optional fields with a default are emitted commented-out so the
 * operator sees both that the var exists and what the effective
 * default is.
 */
function renderField(field: FieldSummary, hint: string): string {
  const lines: string[] = [];
  lines.push(...wrapAsComment(field.description));
  // Conditionally-required fields must render uncommented even though
  // `safeParse(undefined)` succeeded for the field in isolation, or a
  // straight `cp .env.example .env` flow would silently fail at boot.
  if (field.conditionallyRequired) {
    lines.push(`${field.name}=${hint}`);
  } else if (field.optional && field.defaultLiteral === undefined) {
    lines.push(`# ${field.name}=${hint}`);
  } else if (field.optional) {
    lines.push(`# ${field.name}=${field.defaultLiteral}`);
  } else if (field.defaultLiteral !== undefined) {
    lines.push(`${field.name}=${field.defaultLiteral}`);
  } else {
    lines.push(`${field.name}=${hint}`);
  }
  return lines.join('\n');
}

const SERVICE_HEADERS: Record<EunoServiceName, string> = {
  issuer:
    '# Capability Issuer environment configuration.\n# AUTO-GENERATED FROM `@euno/common` EunoConfig schema (R-5).\n# Re-run `euno config dump-template --service issuer > .env.example` after\n# editing the schema. Do not edit this file by hand.',
  gateway:
    '# Tool Gateway environment configuration.\n# AUTO-GENERATED FROM `@euno/common` EunoConfig schema (R-5).\n# Re-run `euno config dump-template --service gateway > .env.example` after\n# editing the schema. Do not edit this file by hand.',
  'db-token-service':
    '# DB Token Service environment configuration.\n# AUTO-GENERATED FROM `@euno/common` EunoConfig schema (R-5).\n# Re-run `euno config dump-template --service db-token-service > .env.example` after\n# editing the schema. Do not edit this file by hand.',
  'storage-grant-service':
    '# Storage Grant Service environment configuration.\n# AUTO-GENERATED FROM `@euno/common` EunoConfig schema (R-5).\n# Re-run `euno config dump-template --service storage-grant-service > .env.example` after\n# editing the schema. Do not edit this file by hand.',
  'agent-runtime':
    '# Agent Runtime environment configuration.\n# AUTO-GENERATED FROM `@euno/common` EunoConfig schema (R-5).\n# Re-run `euno config dump-template --service agent-runtime > .env.example` after\n# editing the schema. Do not edit this file by hand.',
};

/**
 * Render the full `.env.example` file content for a service.  The
 * field order matches the declaration order in
 * {@link ./schema.ts} so reorganising the schema reorganises the
 * template.
 */
export function dumpEnvTemplate(service: EunoServiceName): string {
  const schema = EUNO_CONFIG_SCHEMAS[service];
  // The schema is a `ZodEffects` wrapping the underlying object (because
  // of `superRefine`); reach into the inner shape.
  const innerObject = (() => {
    let s: ZodTypeAny = schema;
    while (s instanceof ZodEffects) {
      s = s._def.schema;
    }
    if (s instanceof ZodObject) return s;
    throw new Error(`expected ZodObject at the core of ${service} schema`);
  })();
  const shape = innerObject.shape as Record<string, ZodTypeAny>;

  // Discover fields that are conditionally required given the schema's
  // *defaults* by parsing an empty environment through the full schema
  // (including `superRefine`). Any issue path produced is a field the
  // operator must set or boot will fail. This is what makes the
  // generated template self-validating: copying it as-is and only
  // filling in the uncommented placeholders yields a valid env.
  const conditionallyRequired = new Set<string>();
  const probe = schema.safeParse({});
  if (!probe.success) {
    for (const issue of probe.error.issues) {
      const head = issue.path[0];
      if (typeof head === 'string' && head in shape) {
        conditionallyRequired.add(head);
      }
    }
  }

  const blocks: string[] = [SERVICE_HEADERS[service], ''];
  for (const [name, type] of Object.entries(shape)) {
    const summary = summariseField(name, type, conditionallyRequired);
    const hint = inferOperatorHint(type);
    blocks.push(renderField(summary, hint));
    blocks.push('');
  }
  // Trim trailing blank line, then ensure file ends with exactly one newline.
  while (blocks.length > 0 && blocks[blocks.length - 1] === '') blocks.pop();
  return `${blocks.join('\n')}\n`;
}

/** Re-export for symmetry with the loader / schema. */
export { EUNO_SERVICE_NAMES };
