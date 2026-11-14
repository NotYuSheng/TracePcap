import { describe, expect, it } from 'vitest';
import type { GraphEdge } from '@/features/network/types';
import { busiestPairs } from '../TrafficCard';

const e = (
  source: string,
  target: string,
  totalBytes: number,
  protocol = 'TCP',
  appName?: string
): GraphEdge =>
  ({
    id: `${source}-${target}-${protocol}`,
    source,
    target,
    label: '',
    data: { protocol, appName, packetCount: 1, totalBytes },
  }) as GraphEdge;

describe('busiestPairs', () => {
  it('adds both directions of a pair together, busiest first', () => {
    const pairs = busiestPairs([e('a', 'b', 10), e('b', 'a', 5, 'UDP', 'DNS'), e('a', 'c', 12)]);
    expect(pairs.map(p => [p.source, p.target, p.bytes])).toEqual([
      ['a', 'b', 15],
      ['a', 'c', 12],
    ]);
    expect(pairs[0].apps).toEqual(['TCP', 'DNS']);
    expect(pairs[0].packets).toBe(2);
  });

  it('keeps the busiest few', () => {
    const edges = Array.from({ length: 12 }, (_, i) => e('h', `p${i}`, i));
    expect(busiestPairs(edges, 3).map(p => p.bytes)).toEqual([11, 10, 9]);
  });
});
