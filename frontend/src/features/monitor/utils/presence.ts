import type { CSSProperties } from 'react';
import type { AbsentEntity, NetworkSettings, NetworkSnapshot } from '../types/monitor.types';

/** Today's behaviour, and what every network has until configured (#488). */
export const DEFAULT_NETWORK_SETTINGS: NetworkSettings = { inactivityMode: 'SNAPSHOTS', inactivityThreshold: 1 };

const DAY_MS = 24 * 60 * 60 * 1000;

function startMs(snap: NetworkSnapshot | undefined): number | null {
  const t = snap?.startTime as unknown as string | number[] | null | undefined;
  if (!t) return null;
  if (Array.isArray(t)) return new Date(t[0], t[1] - 1, t[2], t[3] ?? 0, t[4] ?? 0, t[5] ?? 0).getTime();
  const ms = new Date(t).getTime();
  return Number.isNaN(ms) ? null : ms;
}

/**
 * Whether something missing from the latest capture is merely quiet, or gone (#468, #488).
 * The one place this is decided, so the device, IP and protocol panels can't disagree.
 *
 * - SNAPSHOTS: gone once it has been missing from the last N captures. N = 1 (the default) means
 *   gone as soon as it's missing from the latest one, the behaviour before this setting existed.
 * - DAYS: gone once not seen for more than N days, counted from the latest capture's start (not
 *   today, so reviewing old captures doesn't make everything look gone). Without capture times to
 *   compare, it falls back to "gone".
 *
 * @param lastSeen the snapshot it was last seen in (not the latest one)
 * @param sorted every snapshot, in capture order
 */
export function presenceOf(
  lastSeen: NetworkSnapshot,
  sorted: NetworkSnapshot[],
  settings: NetworkSettings = DEFAULT_NETWORK_SETTINGS
): 'quiet' | 'gone' {
  const threshold = Math.max(1, settings.inactivityThreshold || 1);
  const latest = sorted[sorted.length - 1];
  if (settings.inactivityMode === 'DAYS') {
    const latestMs = startMs(latest);
    const seenMs = startMs(lastSeen);
    if (latestMs === null || seenMs === null) return 'gone';
    return (latestMs - seenMs) / DAY_MS > threshold ? 'gone' : 'quiet';
  }
  const missed = sorted.length - 1 - sorted.findIndex(s => s.id === lastSeen.id);
  return missed >= threshold ? 'gone' : 'quiet';
}

/** Badge styling for something not in the latest capture: struck through if gone, dashed if quiet. */
export function absentBadge(entity: AbsentEntity): { className: string; style: CSSProperties; title: string } {
  if (entity.presence === 'quiet') {
    return {
      className: 'py-0 px-1',
      style: { fontSize: '0.75em', opacity: 0.8, borderStyle: 'dashed' },
      title: `Quiet: not in the latest capture, last seen in ${entity.lastSeenFileName}`,
    };
  }
  return {
    className: 'text-decoration-line-through border-0 py-0 px-1',
    style: { fontSize: '0.75em', opacity: 0.5 },
    title: `No longer seen. Last seen in ${entity.lastSeenFileName}`,
  };
}

/** The rule in words, for legends and the settings dialog. */
export function describeRule(settings: NetworkSettings = DEFAULT_NETWORK_SETTINGS): string {
  const n = Math.max(1, settings.inactivityThreshold || 1);
  if (settings.inactivityMode === 'DAYS') {
    return `no longer seen once not seen for more than ${n} day${n === 1 ? '' : 's'} before the latest capture`;
  }
  return n === 1
    ? 'no longer seen as soon as it is missing from the latest capture'
    : `no longer seen once missing from the last ${n} captures`;
}
