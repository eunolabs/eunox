/**
 * Response-path obligation helpers shared by the stdio and HTTP proxy transports.
 *
 * Obligations are post-enforcement actions applied to an upstream tool-call
 * result *before* it is forwarded to the MCP client.  Currently the only
 * supported obligation is `redactFields`, which strips specified dotted-path
 * fields from JSON text content and `structuredContent`.
 */

import {
  redactConditions,
  hasRedactObligation,
  type CapabilityCondition,
} from '@euno/common-core';

/** Minimal shape of an MCP tool-call result that obligations can operate on. */
export interface ToolCallResult {
  content: Array<{ type: string; text?: string }>;
  structuredContent?: unknown;
  isError?: boolean;
}

/**
 * Apply `redactFields` (and any other response-path) obligations to an
 * upstream tool-call result.
 *
 * Algorithm
 * ─────────
 * 1. For each `type: 'text'` content item whose `text` value is valid JSON,
 *    parse it, pass through {@link redactConditions}, and re-serialise.
 *    Non-JSON text items are returned unchanged — the proxy never silently
 *    attempts JSON parsing and discards failures.
 * 2. When `structuredContent` is present it is also passed through
 *    {@link redactConditions}.  The two representations are treated
 *    independently.
 * 3. Returns the original `result` object unchanged when no conditions have
 *    a `redact` lobe or when no fields match.
 *
 * @param result     - Upstream tool-call result.  MUST NOT be an error result
 *                     (`isError: true`) — callers must guard before invoking.
 * @param conditions - Conditions from the matched {@link CapabilityConstraint}.
 * @returns           A new result object with obligations applied, or `result`
 *                    unchanged when nothing was modified.
 */
export function applyRedactObligations(
  result: ToolCallResult,
  conditions: readonly CapabilityCondition[],
): ToolCallResult {
  if (!hasRedactObligation(conditions)) {
    return result;
  }

  // Apply to each text content item that parses as JSON.
  const newContent = result.content.map((item) => {
    if (item.type !== 'text' || typeof item.text !== 'string') {
      return item;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(item.text);
    } catch {
      // Non-JSON text: leave unchanged.
      return item;
    }
    const redacted = redactConditions(conditions, parsed);
    if (redacted === parsed) {
      return item;
    }
    return { ...item, text: JSON.stringify(redacted) };
  });

  // Apply to structuredContent when present.
  const hasStructured = Object.prototype.hasOwnProperty.call(result, 'structuredContent');
  const newStructured = hasStructured
    ? redactConditions(conditions, result.structuredContent)
    : result.structuredContent;

  const contentChanged = newContent.some((item, i) => item !== result.content[i]);
  const structuredChanged = newStructured !== result.structuredContent;

  if (!contentChanged && !structuredChanged) {
    return result;
  }

  return {
    ...result,
    content: contentChanged ? newContent : result.content,
    ...(hasStructured ? { structuredContent: newStructured } : {}),
  };
}
