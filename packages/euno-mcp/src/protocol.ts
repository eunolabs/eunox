/**
 * MCP protocol version constants for @euno/mcp.
 *
 * The pinned version is recorded in docs/mcp-support.md and must be kept
 * in sync with the `@modelcontextprotocol/sdk` pin in package.json.
 *
 * Updating this constant requires:
 *   1. A corresponding PR to docs/mcp-support.md documenting the new revision
 *      and the rationale for the bump.
 *   2. A CHANGELOG entry in packages/euno-mcp/CHANGELOG.md.
 *   3. CI passing (the integration test suite exercises the MCP handshake).
 *
 * See docs/mcp-support.md for the full support-window policy.
 */

/**
 * The MCP protocol revision string that @euno/mcp commits to support as its
 * primary revision.  This is the value advertised in the `initialize`
 * handshake and validated on every incoming client connection.
 *
 * SDK 1.26.0 supports: 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05, 2024-10-07.
 * We target the latest revision so that hosts on current versions work
 * out of the box.
 */
export const MCP_PROTOCOL_VERSION = '2025-11-25' as const;

/**
 * All protocol revisions that @euno/mcp is willing to negotiate with a
 * connecting client (union of the primary revision and any prior revisions
 * still within the support window).
 *
 * **Manually maintained copy** of the `SUPPORTED_PROTOCOL_VERSIONS` list from
 * `@modelcontextprotocol/sdk` (see `dist/cjs/types.js`).  Must be updated
 * whenever the SDK pin in `package.json` changes — the two lists must remain
 * identical.  Kept as an explicit constant (rather than a live import) so that
 * the accepted revisions are visible in code review and are not silently
 * affected by a transitive SDK upgrade.
 *
 * Source: `SUPPORTED_PROTOCOL_VERSIONS` from @modelcontextprotocol/sdk 1.26.0.
 */
export const MCP_SUPPORTED_PROTOCOL_VERSIONS: readonly string[] = [
  '2025-11-25',
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
  '2024-10-07',
] as const;
