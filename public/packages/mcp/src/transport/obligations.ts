/**
 * Response-path obligation helpers shared by the stdio and HTTP proxy transports.
 *
 * Obligations are post-enforcement actions applied to an upstream tool-call
 * result *before* it is forwarded to the MCP client.  Currently the only
 * supported obligation is `redactFields`, which strips specified dotted-path
 * fields from JSON text content and `structuredContent`.
 *
 * Two entry points are provided:
 *   - {@link applyRedactObligations} — local-mode path; receives the raw
 *     `CapabilityCondition[]` from the matched constraint.
 *   - {@link applyRemoteObligations} — remote-mode path; receives the
 *     `Obligation[]` returned by the hosted gateway's enforce endpoint.
 *     Both `redactFields` and `annotate` obligation types are handled;
 *     `annotate` does not modify the upstream result (it enriches the caller's
 *     audit event, which the caller records separately).
 */

import {
  redactConditions,
  hasRedactObligation,
  type CapabilityCondition,
  type Obligation,
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

/**
 * Apply response-path obligations received from the remote enforcer gateway
 * to an upstream tool-call result.
 *
 * This is the remote-mode counterpart of {@link applyRedactObligations}.
 * The gateway returns `Obligation[]` in the `EnforceResponse`; this function
 * processes them in declaration order:
 *
 * - `redactFields`: strip the listed dotted-path fields from every `text` item
 *   whose content is valid JSON, and from `structuredContent` when present.
 *   Non-JSON text items are left unchanged.
 * - `annotate`: does not modify the upstream result — annotation obligations
 *   are for audit enrichment only.  The caller is responsible for forwarding
 *   annotation key/value pairs to the audit sink.
 *
 * Returns the original `result` object unchanged when no obligations affect
 * the content.
 *
 * @param result      - Upstream tool-call result.  MUST NOT be an error result
 *                      (`isError: true`) — callers must guard before invoking.
 * @param obligations - Obligations from the gateway's `EnforceResponse`.
 * @returns             A new result object with obligations applied, or `result`
 *                      unchanged when nothing was modified.
 */
export function applyRemoteObligations(
  result: ToolCallResult,
  obligations: readonly Obligation[],
): ToolCallResult {
  // Collect all redact paths from `redactFields` obligations.
  const redactPaths: string[] = [];
  for (const obligation of obligations) {
    if (obligation.type === 'redactFields') {
      redactPaths.push(...obligation.paths);
    }
    // `annotate` obligations are handled by the caller (audit enrichment only);
    // they do not modify the upstream result.
  }

  if (redactPaths.length === 0) {
    return result;
  }

  // Synthesise a single CapabilityCondition-shaped record so we can reuse the
  // shared `redactConditions` helper without duplicating the traversal logic.
  // The obligation paths have already been validated by the gateway, so we do
  // not re-validate them here.
  const syntheticConditions: readonly CapabilityCondition[] = [
    { type: 'redactFields', fields: redactPaths },
  ];

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
    const redacted = redactConditions(syntheticConditions, parsed);
    if (redacted === parsed) {
      return item;
    }
    return { ...item, text: JSON.stringify(redacted) };
  });

  // Apply to structuredContent when present.
  const hasStructured = Object.prototype.hasOwnProperty.call(result, 'structuredContent');
  const newStructured = hasStructured
    ? redactConditions(syntheticConditions, result.structuredContent)
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
