import * as path from 'node:path';
import { createRequire } from 'node:module';
import {
  registerCustomCondition,
  getCustomConditionHandlers,
  ManifestValidationError,
  type AgentCapabilityManifest,
  type CapabilityCondition,
} from '@euno/common-core';

type RegisterCustomConditionFn = typeof registerCustomCondition;

interface CustomConditionModuleApi {
  registerCustomCondition: RegisterCustomConditionFn;
}

type CustomConditionModuleDefaultExport =
  (api: CustomConditionModuleApi) => void | Promise<void>;

const runtimeRequire = createRequire(__filename);

function toErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Load and initialize custom-condition handler modules.
 *
 * Every module must default-export a function that receives
 * `{ registerCustomCondition }`.
 */
export async function loadCustomConditionModules(modulePaths: readonly string[]): Promise<void> {
  for (const modulePath of modulePaths) {
    const resolvedPath = path.resolve(modulePath);
    let imported: unknown;
    try {
      imported = runtimeRequire(resolvedPath);
    } catch (err) {
      throw new Error(
        `Failed to load custom condition module '${modulePath}' (${resolvedPath}): ${toErrorMessage(err)}`,
      );
    }

    const init =
      typeof imported === 'function'
        ? imported
        : (imported as { default?: unknown }).default;
    if (typeof init !== 'function') {
      throw new Error(
        `Custom condition module '${modulePath}' must export a default function`,
      );
    }

    try {
      await (init as CustomConditionModuleDefaultExport)({ registerCustomCondition });
    } catch (err) {
      throw new Error(
        `Custom condition module '${modulePath}' failed during initialization: ${toErrorMessage(err)}`,
      );
    }
  }
}

/**
 * Validate that every `custom` condition referenced by `manifest` has a
 * registered handler in the process-wide registry.
 */
export function validateCustomConditionRegistrations(manifest: AgentCapabilityManifest): void {
  const handlers = getCustomConditionHandlers();
  const requiredLen = manifest.requiredCapabilities.length;
  const allConstraints = [
    ...manifest.requiredCapabilities,
    ...(manifest.optionalCapabilities ?? []),
  ];

  for (let ci = 0; ci < allConstraints.length; ci++) {
    const constraint = allConstraints[ci];
    if (!constraint) continue;
    const capArray = ci < requiredLen ? 'requiredCapabilities' : 'optionalCapabilities';
    const capIdx = ci < requiredLen ? ci : ci - requiredLen;
    const conditions = constraint.conditions;
    if (!conditions) continue;

    for (let di = 0; di < conditions.length; di++) {
      const condition = conditions[di] as CapabilityCondition | undefined;
      if (!condition || condition.type !== 'custom') continue;
      if (typeof condition.name !== 'string' || condition.name.length === 0) continue;
      if (handlers.has(condition.name)) continue;

      const jsonPath = `${capArray}[${capIdx}].conditions[${di}].name`;
      throw new ManifestValidationError(
        `${jsonPath}: custom condition '${condition.name}' has no registered handler`,
        jsonPath,
      );
    }
  }
}
