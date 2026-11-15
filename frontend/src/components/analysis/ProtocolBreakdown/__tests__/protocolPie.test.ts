import { describe, expect, it } from 'vitest';
import type { ProtocolStats } from '@/types';
import { MAX_PIE_PROTOCOLS, OTHER_SLICE, toPieSlices } from '../protocolPie';

const stat = (protocol: string, count: number): ProtocolStats => ({
  protocol,
  count,
  percentage: 0,
  bytes: 0,
});

const manyStats = (count: number) =>
  Array.from({ length: count }, (_, i) => stat(`0X${i}`, count - i));

describe('toPieSlices', () => {
  it('groups everything past the biggest protocols into Other', () => {
    const slices = toPieSlices(manyStats(391));

    expect(slices).toHaveLength(MAX_PIE_PROTOCOLS + 1);
    expect(slices[0].name).toBe('0X0');
    expect(slices[MAX_PIE_PROTOCOLS].name).toBe(OTHER_SLICE);
  });

  it('keeps the packet total', () => {
    const stats = manyStats(391);
    const total = (values: number[]) => values.reduce((sum, value) => sum + value, 0);

    expect(total(toPieSlices(stats).map(slice => slice.value))).toBe(
      total(stats.map(s => s.count))
    );
  });

  it('adds no Other slice when everything fits', () => {
    expect(toPieSlices([stat('TCP', 2), stat('UDP', 1)]).map(s => s.name)).toEqual(['TCP', 'UDP']);
  });

  it('folds the parser OTHER label into the Other slice', () => {
    expect(toPieSlices([stat('OTHER', 50), stat('TCP', 1)])).toEqual([
      { name: 'TCP', value: 1 },
      { name: OTHER_SLICE, value: 50 },
    ]);
  });
});
