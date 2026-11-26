import type { CaptureContext, VantagePoint } from '@/types';

/** "On a honeypot or sensor (192.168.100.28)", or null when undetermined. */
export function vantageDescribed(v: VantagePoint): string | null {
  if (!v.label) return null;
  return v.host ? `${v.label} (${v.host})` : v.label;
}

/** The capture context in one line: "On the internet uplink · inferred · complete · 33 min". */
export function contextParts(ctx: CaptureContext): { vantage: string; grade: string | null; rest: string[] } {
  const v = ctx.vantage;
  const described = vantageDescribed(v);
  const grade = !described ? null
    : v.basis === 'HUMAN' ? 'set by an analyst'
      : v.contested ? 'inferred, contested' : 'inferred';
  const completeness = { complete: 'complete', partial: 'partial', notes: 'complete, with notes' }[ctx.completeness.level];
  // The time span's label is "33 min, 2024-08-15 08:09 to 08:42 UTC": the line takes the duration.
  const duration = ctx.timeSpan.label?.split(',')[0] ?? null;
  return {
    vantage: described ?? 'Vantage point not determined',
    grade,
    rest: [completeness, duration].filter((s): s is string => !!s),
  };
}
