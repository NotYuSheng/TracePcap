// formatBytes is the shared formatter now (#733); this module keeps the local import
// path its sections already use.
export { formatBytes } from '@/utils/formatters';

import type { CSSProperties } from 'react';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';

// NOTE: these mirror utils/formatters but keep this modal's historical formatting
// (2-decimal bytes, default-locale numbers). Reconciled separately in the helper-dedup slice.

export function formatNumber(num: number): string {
  return num.toLocaleString();
}

export function formatSnapTime(snap: NetworkSnapshot): string {
  if (!snap.startTime) return snap.fileName;
  const ms = parseDateTime(snap.startTime);
  return new Date(ms).toLocaleDateString('en-GB', { month: 'short', day: 'numeric', year: 'numeric' });
}

export function stringHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0xffffffff;
  return Math.abs(h) % 360;
}

export function hashBadgeStyle(s: string): CSSProperties {
  const hue = stringHue(s);
  return {
    '--badge-hue': hue,
    background: `hsl(${hue}, 40%, 88%)`,
    color: `hsl(${hue}, 50%, 28%)`,
    border: `1px solid hsl(${hue}, 35%, 72%)`,
  } as CSSProperties;
}
