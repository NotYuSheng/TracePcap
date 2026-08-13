/**
 * One severity palette for monitor change events (#733 finding 6).
 *
 * Four definitions existed and they disagreed, most consequentially about INFO — cyan in the
 * event list, grey in the security tab and **green** in the snapshot modal. Green is the success
 * colour everywhere else in the app, so an informational event read as "this is fine" in one
 * panel and as neutral in another. WARNING was likewise Bootstrap yellow in one place and orange
 * in two others.
 *
 * Exported as hex rather than Bootstrap class names on purpose: `text-warning` is #ffc107 while
 * every other panel drew #fd7e14, so a map of class names and a map of hexes for the same three
 * severities is two definitions again. One map, used for both text and fills.
 */
export type MonitorSeverity = 'CRITICAL' | 'WARNING' | 'INFO';

const SEVERITY_HEX: Record<MonitorSeverity, string> = {
  CRITICAL: '#dc3545',
  WARNING: '#fd7e14',
  // Grey, not green: informational is neutral, and green means "good" elsewhere in the app.
  INFO: '#6c757d',
};

/** Fallback keeps an unrecognised severity visible rather than transparent. */
export function severityHex(severity: string | null | undefined): string {
  return SEVERITY_HEX[severity as MonitorSeverity] ?? SEVERITY_HEX.INFO;
}

const SEVERITY_ICON: Record<MonitorSeverity, string> = {
  CRITICAL: 'bi-exclamation-circle-fill',
  WARNING: 'bi-exclamation-triangle-fill',
  INFO: 'bi-info-circle-fill',
};

export function severityIcon(severity: string | null | undefined): string {
  return SEVERITY_ICON[severity as MonitorSeverity] ?? 'bi-circle-fill';
}

/** Bootstrap `bg` variant, for the SGDS/Bootstrap Badge in the legend copy. */
export function severityBadgeBg(severity: string | null | undefined): string {
  switch (severity) {
    case 'CRITICAL':
      return 'danger';
    case 'WARNING':
      return 'warning';
    default:
      return 'secondary';
  }
}
