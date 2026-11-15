import { describe, expect, it } from 'vitest'
import { animatedEdges } from '../trafficParticles'

function fakeSigma(edges: { key: string; bytes: number; bidirectional?: boolean }[]) {
  return {
    getGraph: () => ({
      forEachEdge: (cb: (key: string, attrs: Record<string, unknown>) => void) =>
        edges.forEach(e => cb(e.key, { totalBytes: e.bytes, bidirectional: e.bidirectional })),
    }),
  } as never
}

describe('animatedEdges', () => {
  it('animates the busiest edges first, with a stable phase each', () => {
    const out = animatedEdges(fakeSigma([
      { key: 'small', bytes: 10 },
      { key: 'big', bytes: 10_000, bidirectional: true },
    ]))
    expect(out.map(e => e.key)).toEqual(['big', 'small'])
    expect(out[0].bidirectional).toBe(true)
    expect(out[0].phase).toBeGreaterThanOrEqual(0)
    expect(out[0].phase).toBeLessThan(1)
    expect(animatedEdges(fakeSigma([{ key: 'big', bytes: 1 }]))[0].phase).toBe(out[0].phase)
  })

  it('caps how many edges animate on a huge graph', () => {
    const many = Array.from({ length: 1000 }, (_, i) => ({ key: `e${i}`, bytes: i }))
    const out = animatedEdges(fakeSigma(many))
    expect(out).toHaveLength(400)
    expect(out[0].key).toBe('e999')
  })
})
