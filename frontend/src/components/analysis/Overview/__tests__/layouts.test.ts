import { describe, expect, it } from 'vitest'

import { flowLayout, groupNames, squarify } from '../layouts'

describe('squarify', () => {
  it('fills the box exactly, each tile in proportion to its value', () => {
    const tiles = squarify(
      [6, 6, 4, 3, 2, 2, 1].map((value, i) => ({ value, item: i })),
      600,
      400,
    )
    expect(tiles).toHaveLength(7)
    const area = tiles.reduce((s, t) => s + t.w * t.h, 0)
    expect(area).toBeCloseTo(600 * 400, 0)
    // 6 of 24 → a quarter of the box.
    expect(tiles.find(t => t.item === 0)!.w * tiles.find(t => t.item === 0)!.h).toBeCloseTo(60000, 0)
    for (const t of tiles) {
      expect(t.x).toBeGreaterThanOrEqual(-0.001)
      expect(t.y).toBeGreaterThanOrEqual(-0.001)
      expect(t.x + t.w).toBeLessThanOrEqual(600.001)
      expect(t.y + t.h).toBeLessThanOrEqual(400.001)
    }
  })

  it('drops empty items rather than drawing zero-size tiles', () => {
    expect(squarify([{ value: 5, item: 'a' }, { value: 0, item: 'b' }], 100, 100)).toHaveLength(1)
  })
})

describe('flowLayout', () => {
  it('stacks each column biggest first and makes bands as thick as their share', () => {
    const { left, right, bands } = flowLayout(
      [
        { from: 'A', to: 'X', value: 60 },
        { from: 'B', to: 'X', value: 30 },
        { from: 'A', to: 'Y', value: 10 },
      ],
      108,
      4,
    )
    expect(left.map(n => n.id)).toEqual(['A', 'B'])
    expect(right.map(n => n.id)).toEqual(['X', 'Y'])
    // 100 units over 104px (108 minus one 4px gap).
    expect(left[0].h).toBeCloseTo(72.8, 1)
    const ax = bands.find(b => b.from === 'A' && b.to === 'X')!
    const ay = bands.find(b => b.from === 'A' && b.to === 'Y')!
    // A's bands sit one under the other at A, starting at A's top.
    expect(ax.y0).toBe(left[0].y)
    expect(ay.y0).toBeCloseTo(ax.y0 + ax.h0, 6)
  })
})

describe('groupNames', () => {
  it('drops the AS number, unless two groups would then share a name', () => {
    const n = groupNames([
      { id: 'asn:AS3320', label: 'Deutsche Telekom AG (AS3320)' },
      { id: 'asn:AS8075', label: 'Microsoft Corporation (AS8075)' },
      { id: 'asn:AS8068', label: 'Microsoft Corporation (AS8068)' },
    ])
    expect(n.get('asn:AS3320')).toBe('Deutsche Telekom AG')
    expect(n.get('asn:AS8075')).toBe('Microsoft Corporation (AS8075)')
    expect(n.get('asn:AS8068')).toBe('Microsoft Corporation (AS8068)')
  })
})
