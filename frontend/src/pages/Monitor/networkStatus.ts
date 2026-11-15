import type { CaptureMark, Network } from '@/features/monitor/types/monitor.types';

export type NetworkStatusKey = 'empty' | 'baseline' | 'critical' | 'review' | 'clear';

export interface NetworkStatus {
  key: NetworkStatusKey;
  label: string;
  /** The row's one next action. */
  action: string;
  /** Where the action goes. */
  to: string;
}

/** One status per network, and what to do next (Monitor B). */
export function networkStatus(n: Network): NetworkStatus {
  const base = `/monitor/${n.id}`;
  if (n.snapshotCount === 0) {
    return { key: 'empty', label: 'No captures yet', action: 'Add the first capture', to: `${base}?add=1` };
  }
  if (n.criticalChanges > 0) {
    return {
      key: 'critical',
      label: `${n.criticalChanges} critical to review`,
      action: 'Review',
      to: `${base}?section=changes`,
    };
  }
  if (n.warningChanges > 0) {
    return {
      key: 'review',
      label: `${n.warningChanges} change${n.warningChanges === 1 ? '' : 's'} to review`,
      action: 'Review',
      to: `${base}?section=changes`,
    };
  }
  if (n.snapshotCount === 1) {
    return { key: 'baseline', label: 'Baseline set', action: 'Add a capture', to: `${base}?add=1` };
  }
  return { key: 'clear', label: 'Up to date', action: 'Open', to: base };
}

/** The colour of a capture's dot on the track. */
export function markTone(m: CaptureMark): 'baseline' | 'none' | 'warning' | 'critical' {
  if (m.baseline) return 'baseline';
  if (m.changes === 'CRITICAL') return 'critical';
  if (m.changes === 'WARNING') return 'warning';
  return 'none';
}

export type NetworkFilter = 'all' | 'review' | 'empty';

export function matchesFilter(n: Network, f: NetworkFilter): boolean {
  if (f === 'all') return true;
  const k = networkStatus(n).key;
  return f === 'review' ? k === 'review' || k === 'critical' : k === 'empty';
}
