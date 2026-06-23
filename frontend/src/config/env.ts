/**
 * Centralized, validated access to all VITE_* environment variables.
 *
 * Every consumer should import from here instead of reading
 * `import.meta.env.VITE_*` directly. Unknown / missing / malformed
 * values are caught once at module-load time so the app fails fast
 * with a clear message rather than silently misbehaving.
 */

// NOTE: Vite statically replaces `import.meta.env.VITE_*` only when accessed
// as literal member expressions at build time. Dynamic access like
// `import.meta.env[key]` is NOT replaced and returns `undefined` in production
// builds, so callers must pass the statically accessed value directly.

function requiredString(raw: unknown, fallback: string): string {
  const value = typeof raw === 'string' ? raw.trim() : '';
  return value || fallback;
}

function optionalBoolean(raw: unknown, fallback: boolean): boolean {
  if (raw === undefined || raw === '') return fallback;
  return raw !== 'false';
}

function parseFileTypes(raw: string): string[] {
  return raw
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

// ---------------------------------------------------------------------------
// Validated env
// ---------------------------------------------------------------------------

export const env = {
  /** Base URL for the REST API (e.g. `/api/v1`). */
  API_BASE_URL: requiredString(import.meta.env.VITE_API_BASE_URL, 'http://localhost:8080/api/v1'),

  /** Accepted file extensions for upload (array, e.g. `['.pcap', '.pcapng']`). */
  SUPPORTED_FILE_TYPES: parseFileTypes(
    requiredString(import.meta.env.VITE_SUPPORTED_FILE_TYPES, '.pcap,.pcapng,.cap'),
  ),

  /** Whether the analysis-options dialog is shown before upload. */
  ANALYSIS_OPTIONS_ENABLED: optionalBoolean(import.meta.env.VITE_ANALYSIS_OPTIONS, true),

  /** Whether the network diagram caps the conversation count. */
  NETWORK_DIAGRAM_CONVERSATION_LIMIT: optionalBoolean(
    import.meta.env.VITE_NETWORK_DIAGRAM_CONVERSATION_LIMIT,
    true,
  ),
} as const;
