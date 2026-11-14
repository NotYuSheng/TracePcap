import { describe, expect, it } from 'vitest'
import type { GraphEdge } from '../../types'
import { activeInWindow, bytesHistogram, clampWindow, timeBounds } from '../timeWindow'

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
