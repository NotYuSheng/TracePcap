const LABEL: Record<string, string> = { GLOBAL: 'global', CAPTURE: 'capture' };

/**
 * Which scope a rule match comes from (#925 phase 3), shown inside its badge: "global",
 * "capture", or the network's name. Nothing when the scope isn't known.
 */
export function RuleScopeTag({ scope }: { scope?: string }) {
  // A network rule's scope arrives as "NETWORK:<network name>" and is labelled with the name.
  const label = !scope ? null : scope.startsWith('NETWORK:') ? scope.slice(8) : (LABEL[scope] ?? scope.toLowerCase());
  if (!label) return null;
  return (
    <span className="ms-1" style={{ opacity: 0.75, fontWeight: 400, fontSize: '0.85em' }}>
      · {label}
    </span>
  );
}
