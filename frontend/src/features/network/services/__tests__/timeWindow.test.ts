import { describe, expect, it } from 'vitest'
import type { GraphEdge } from '../../types'
import { activeInWindow, bytesHistogram, clampWindow, timeBounds, unseenByWindowEnd, activeSegments, playWindow } from '../timeWindow'

function edge(id: string, src: string, dst: string, start?: number, end?: number, bytes = 100): GraphEdge {
  return { id, source: src, target: dst, label: '', data: { protocol: 'TCP', packetCount: 1, totalBytes: bytes, conversationId: id, bidirectional: true, startTime: start, endTime: end } } as GraphEdge
}

describe('timeWindow', () => {
  const edges = [
    edge('laptop-mail', 'laptop', 'mail', 1000, 2000),
    edge('phone-beacon', 'phone', 'c2', 5000, 6000),
    edge('timeless', 'a', 'b'),
  ]

  it('spans the first start to the last end, ignoring conversations with no time', () => {
    expect(timeBounds(edges)).toEqual({ from: 1000, to: 6000 })
    expect(timeBounds([edge('x', 'a', 'b')])).toBeNull()
  })

  it('a window shows the conversations that overlap it and the nodes at their ends', () => {
    const early = activeInWindow(edges, { from: 0, to: 3000 })
    expect([...early.edgeIds]).toContain('laptop-mail')
    expect([...early.edgeIds]).not.toContain('phone-beacon')
    expect(early.nodeIds.has('laptop')).toBe(true)
    expect(early.nodeIds.has('phone')).toBe(false)
    // A conversation that started before the window and is still going counts.
    expect(activeInWindow(edges, { from: 1500, to: 1600 }).edgeIds.has('laptop-mail')).toBe(true)
    // One with no time never silently disappears.
    expect(early.edgeIds.has('timeless')).toBe(true)
  })

  it("spreads a conversation's bytes over the buckets it spans", () => {
    const h = bytesHistogram([edge('long', 'a', 'b', 0 + 1, 1001, 1000)], { from: 1, to: 1001 }, 10)
    expect(h.every(v => Math.abs(v - 100) < 1e-6)).toBe(true)
    const spike = bytesHistogram([edge('short', 'a', 'b', 500, 500, 70)], { from: 0, to: 1000 }, 10)
    expect(spike[5]).toBe(70)
    expect(spike.reduce((a, b) => a + b, 0)).toBe(70)
  })

  it('keeps a window inside the capture', () => {
    expect(clampWindow(5500, 1000, { from: 1000, to: 6000 })).toEqual({ from: 5000, to: 6000 })
    expect(clampWindow(0, 1000, { from: 1000, to: 6000 })).toEqual({ from: 1000, to: 2000 })
    expect(clampWindow(0, 99999, { from: 1000, to: 6000 })).toEqual({ from: 1000, to: 6000 })
  })
})

describe('unseenByWindowEnd', () => {
  it('is the nodes none of whose conversations had started by the window end', () => {
    const e = (id: string, s: string, t: string, start: number) =>
      ({ id, source: s, target: t, label: '', data: { protocol: 'TCP', packetCount: 1, totalBytes: 1, conversationId: id, bidirectional: true, startTime: start, endTime: start + 10 } }) as never
    const unseen = unseenByWindowEnd([e('a', 'laptop', 'mail', 100), e('b', 'phone', 'c2', 900)], { from: 0, to: 500 })
    expect([...unseen].sort()).toEqual(['c2', 'phone'])
  })
})

describe('playing a capture with long idle gaps', () => {
  // Two bursts six years apart, as in a capture merged from two days.
  const YEAR = 365 * 86_400_000;
  const edges = [
    edge('a', 'x', 'y', 1_000, 2_000),
    edge('b', 'x', 'z', 3_000, 9_000),
    edge('c', 'x', 'w', 6 * YEAR, 6 * YEAR + 5_000),
  ];
  const bounds = { from: 1_000, to: 6 * YEAR + 5_000 };

  it('finds the two bursts and leaves the gap out', () => {
    expect(activeSegments(edges, bounds)).toEqual([
      { from: 1_000, to: 9_000 },
      { from: 6 * YEAR, to: 6 * YEAR + 5_000 },
    ]);
  });

  it('keeps a capture with only short or relatively small gaps as one stretch', () => {
    // 10-minute lulls in a 30-minute capture: under an hour, so they play as they are.
    const lulls = [0, 1, 2, 3].map(i => edge(`l${i}`, 'x', 'y', 1_000_000 + i * 600_000, 1_001_000 + i * 600_000));
    expect(activeSegments(lulls, { from: 1_000_000, to: 2_801_000 })).toHaveLength(1);
  });

  it('maps played time onto each burst in turn, never across the gap', () => {
    const segs = activeSegments(edges, bounds);
    expect(playWindow(segs, 0, 2_000)).toEqual({ from: 1_000, to: 3_000 });
    // 8 s of the first burst played: the next position is the second burst's start.
    expect(playWindow(segs, 8_000, 2_000)).toEqual({ from: 6 * YEAR, to: 6 * YEAR + 2_000 });
    expect(playWindow(segs, 7_500, 2_000)).toEqual({ from: 8_500, to: 9_000 });
  });
});
