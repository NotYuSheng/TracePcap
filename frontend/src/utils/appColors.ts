import ColorHash from 'color-hash';

const colorHash = new ColorHash({ lightness: 0.45, saturation: 0.6 });

export function getAppColor(appName: string): string {
  return colorHash.hex(appName);
}

export function getCategoryColor(category: string): string {
  return colorHash.hex(category);
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: '#dc3545', text: '#fff' },
  high:     { bg: '#fd7e14', text: '#fff' },
  medium:   { bg: '#e67e22', text: '#fff' },
  low:      { bg: '#6f42c1', text: '#fff' },
};

/** Distinct colour for nDPI built-in risk flags — clearly different from custom signature severities. */
export const RISK_BADGE = { bg: '#ffc107', text: '#212529' };

export function getSeverityColor(severity: string): { bg: string; text: string } {
  return SEVERITY_COLORS[severity?.toLowerCase()] ?? SEVERITY_COLORS.low;
}

/**
 * Returns '#000' or '#fff' depending on which has better contrast
 * against the given hex background colour (uses WCAG relative luminance).
 */
export function getTextColor(hexBackground: string): string {
  const r = parseInt(hexBackground.slice(1, 3), 16);
  const g = parseInt(hexBackground.slice(3, 5), 16);
  const b = parseInt(hexBackground.slice(5, 7), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance > 0.5 ? '#000' : '#fff';
}
