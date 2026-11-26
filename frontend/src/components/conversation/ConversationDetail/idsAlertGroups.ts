import type { IdsAlert } from '@/types';

/** Alerts that differ only in time, folded into one row with a count and a time span. */
export interface AlertGroup {
  first: IdsAlert;
  count: number;
  from?: number;
  to?: number;
}

/** Folds repeats (65 identical check-ins) by rule, direction and request; first-seen order. */
export function groupIdsAlerts(alerts: IdsAlert[]): AlertGroup[] {
  const groups = new Map<string, AlertGroup>();
  for (const a of alerts) {
    const key = [a.sid, a.srcIp, a.httpMethod, a.httpUrl].join('|');
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { first: a, count: 1, from: a.time, to: a.time });
    } else {
      g.count += 1;
      if (a.time != null) {
        if (g.from == null || a.time < g.from) g.from = a.time;
        if (g.to == null || a.time > g.to) g.to = a.time;
      }
    }
  }
  return [...groups.values()];
}

/**
 * The IDS alerts group's note (#1284): "N fired", or, when the records stopped at their cap,
 * "N fired · first K shown" so the rows aren't read as all of them.
 */
export function alertsFiredNote(kept: number, total?: number | null): string {
  const fired = Math.max(total ?? 0, kept);
  const n = fired.toLocaleString('en-US');
  if (fired > kept && kept === 0) return `${n} fired · no records kept`;
  return fired > kept ? `${n} fired · first ${kept.toLocaleString('en-US')} shown` : `${n} fired`;
}
