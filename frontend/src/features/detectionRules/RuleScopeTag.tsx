const LABEL: Record<string, string> = { GLOBAL: 'global', CAPTURE: 'capture' };

/**
 * Which scope a rule match comes from (#925 phase 3), shown inside its badge: "global" or
 * "capture" (network names arrive with network rules). Nothing when the scope isn't known.
 */
export function RuleScopeTag({ scope }: { scope?: string }) {
  const label = scope ? (LABEL[scope] ?? scope.toLowerCase()) : null;
  if (!label) return null;
  return (
    <span className="ms-1" style={{ opacity: 0.75, fontWeight: 400, fontSize: '0.85em' }}>
      · {label}
    </span>
  );
}
