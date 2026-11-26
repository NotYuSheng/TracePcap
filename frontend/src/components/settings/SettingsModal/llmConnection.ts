/** The settings the LLM connection form changes together. */
export const LLM_CONNECTION_KEYS = ['LLM_API_BASE_URL', 'LLM_API_KEY', 'LLM_MODEL'] as const;

/** 262144 → "256k context". */
export function contextLabel(tokens?: number | null): string {
  if (!tokens) return '';
  return tokens >= 1024 ? `${Math.round(tokens / 1024)}k context` : `${tokens} context`;
}
