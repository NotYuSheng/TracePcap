import type { CSSProperties } from 'react';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';

// NOTE: these mirror utils/formatters but keep this modal's historical formatting
// (2-decimal bytes, default-locale numbers). Reconciled separately in the helper-dedup slice.
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  // Clamp so multi-TB totals (prod captures reach tens of TB) never index past the unit list and
  // render "1.00 undefined".
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

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
