import type { ProtocolStats } from '@/types';

/** The most protocols the pie draws individually; the rest share one grey slice. */
export const MAX_PIE_PROTOCOLS = 9;

export const OTHER_SLICE = 'Other';

export interface PieSlice {
  name: string;
  value: number;
}

/** The biggest protocols, then an Other slice holding the rest. Expects stats sorted by count. */
export function toPieSlices(stats: ProtocolStats[]): PieSlice[] {
  const named = stats.filter(stat => stat.protocol.toUpperCase() !== OTHER_SLICE.toUpperCase());
  const slices = named
    .slice(0, MAX_PIE_PROTOCOLS)
    .map(stat => ({ name: stat.protocol, value: stat.count }));
  const shown = new Set(slices.map(slice => slice.name));
  const rest = stats
    .filter(stat => !shown.has(stat.protocol))
    .reduce((sum, stat) => sum + stat.count, 0);
  return rest > 0 ? [...slices, { name: OTHER_SLICE, value: rest }] : slices;
}
