import { describe, expect, it } from 'vitest'
import { CELL_H, CELL_W, NODE_TOP } from '../networkGroups'
import { bendEdges, bendFor, blockers, curvePoint, hitsOfCurve, pointAlong, routeOrthogonal, CLEARANCE, type Pt } from '../edgeRouting'

// office_showcase.pcap's Servers group: printers on the top row, the cameras and the NAS below.
const x0 = 100
const y0 = 200
const at = (col: number, row: number): Pt => ({ x: x0 + col * CELL_W + CELL_W / 2, y: y0 + row * CELL_H + NODE_TOP })
const devices: Record<string, [number, number]> = {
  'HP-LaserJet-3F': [0, 0],
  'HP-LaserJet-2F': [1, 0],
  'CAM-ENTRANCE': [0, 1],
  'CAM-CARPARK': [1, 1],
  'NAS-OFFICE': [2, 1],
}
const pos = new Map(Object.entries(devices).map(([id, [c, r]]) => [id, at(c, r)]))
const edge = (source: string, target: string, curvature = 0) => ({ key: `${source}>${target}`, source, target, curvature })

const minDistance = (path: (u: number) => Pt, p: Pt) => {
  let best = Infinity
  for (let i = 1; i < 200; i++) {
    const q = path(i / 200)
    best = Math.min(best, Math.hypot(q.x - p.x, q.y - p.y))
  }
  return best
}

describe('which edges run through a device', () => {
  it('finds the camera between the entrance camera and the NAS', () => {
    expect(blockers(pos.get('CAM-ENTRANCE')!, pos.get('NAS-OFFICE')!, pos, ['CAM-ENTRANCE', 'NAS-OFFICE'])).toEqual(['CAM-CARPARK'])
  })

  it('leaves neighbours alone', () => {
    expect(blockers(pos.get('CAM-CARPARK')!, pos.get('NAS-OFFICE')!, pos, ['CAM-CARPARK', 'NAS-OFFICE'])).toEqual([])
  })
})

describe('bend: only a blocked edge bends, just enough to clear', () => {
  it('bends ENTRANCE → NAS around CARPARK and keeps CARPARK → NAS straight', () => {
    const bends = bendEdges([edge('CAM-ENTRANCE', 'NAS-OFFICE'), edge('CAM-CARPARK', 'NAS-OFFICE')], pos)
    expect([...bends.keys()]).toEqual(['CAM-ENTRANCE>NAS-OFFICE'])

    const s = pos.get('CAM-ENTRANCE')!
    const t = pos.get('NAS-OFFICE')!
    const c = bends.get('CAM-ENTRANCE>NAS-OFFICE')!
    // The arc passes CARPARK at least the clearance away…
    expect(minDistance(u => curvePoint(s, t, c, u), pos.get('CAM-CARPARK')!)).toBeGreaterThanOrEqual(CLEARANCE * 0.95)
    // …and doesn't bow into the printer row above instead.
    expect(minDistance(u => curvePoint(s, t, c, u), pos.get('HP-LaserJet-2F')!)).toBeGreaterThan(CLEARANCE * 0.9)
  })

  it('bends diagonals too', () => {
    const p = new Map<string, Pt>([['a', { x: 0, y: 0 }], ['m', { x: 100, y: 100 }], ['b', { x: 200, y: 200 }]])
    expect(bendFor(p.get('a')!, p.get('b')!, p, ['a', 'b'])).not.toBeNull()
  })

  it('leaves an unblocked edge straight', () => {
    expect(bendFor(pos.get('HP-LaserJet-3F')!, pos.get('HP-LaserJet-2F')!, pos, ['HP-LaserJet-3F', 'HP-LaserJet-2F'])).toBeNull()
  })
})

describe('bend: a fanned-out pair bends together', () => {
  it('moves both directions of ENTRANCE ⇄ NAS off CARPARK, to the same side', () => {
    // Two edges between the same devices, one each way, fanned apart a little: both still clip CARPARK.
    const there = edge('CAM-ENTRANCE', 'NAS-OFFICE', 0.05)
    const back = edge('NAS-OFFICE', 'CAM-ENTRANCE', 0.05)
    const bends = bendEdges([there, back], pos)
    const s = pos.get('CAM-ENTRANCE')!
    const t = pos.get('NAS-OFFICE')!
    expect(hitsOfCurve(s, t, bends.get(there.key)!, pos, ['CAM-ENTRANCE', 'NAS-OFFICE'])).toBe(0)
    expect(hitsOfCurve(t, s, bends.get(back.key)!, pos, ['NAS-OFFICE', 'CAM-ENTRANCE'])).toBe(0)
    // Same physical side: the reverse edge's curvature has the opposite sign around its own fan offset.
    expect(Math.sign(bends.get(there.key)! - 0.05)).toBe(-Math.sign(bends.get(back.key)! - 0.05))
  })
})

describe('along the gaps: a blocked edge gets a right-angle route around the devices', () => {
  const clearOf = (r: Pt[], ids: string[], p: Map<string, Pt>) =>
    ids.every(id => minDistance(u => pointAlong(r, u), p.get(id)!) > 30)

  it('routes ENTRANCE → NAS around CARPARK, and leaves CARPARK → NAS alone', () => {
    const routes = routeOrthogonal([edge('CAM-ENTRANCE', 'NAS-OFFICE'), edge('CAM-CARPARK', 'NAS-OFFICE')], pos)
    expect([...routes.keys()]).toEqual(['CAM-ENTRANCE>NAS-OFFICE'])
    const r = routes.get('CAM-ENTRANCE>NAS-OFFICE')!
    expect(r[0]).toEqual(pos.get('CAM-ENTRANCE'))
    expect(r[r.length - 1]).toEqual(pos.get('NAS-OFFICE'))
    for (let i = 1; i < r.length; i++) expect(r[i].x === r[i - 1].x || r[i].y === r[i - 1].y).toBe(true)
    expect(clearOf(r, ['CAM-CARPARK', 'HP-LaserJet-2F', 'HP-LaserJet-3F'], pos)).toBe(true)
    // A few long legs, not a staircase.
    expect(r.length).toBeLessThanOrEqual(6)
  })

  it('routes down a column past the device in the middle', () => {
    const p = new Map<string, Pt>([['top', at(0, 0)], ['mid', at(0, 1)], ['bottom', at(0, 2)]])
    const r = routeOrthogonal([edge('top', 'bottom')], p).get('top>bottom')!
    expect(clearOf(r, ['mid'], p)).toBe(true)
  })

  it('routes between groups too: from inside a grid to a device elsewhere', () => {
    // A 3×3 grid, and a gateway off to the right: the middle device's edge must thread out.
    const p = new Map<string, Pt>()
    for (let c = 0; c < 3; c++) for (let r = 0; r < 3; r++) p.set(`d${c}${r}`, at(c, r))
    p.set('gw', { x: at(2, 1).x + 3 * CELL_W, y: at(2, 1).y })
    const r = routeOrthogonal([edge('d01', 'gw')], p).get('d01>gw')!
    expect(r).toBeDefined()
    expect(clearOf(r, [...p.keys()].filter(k => k !== 'd01' && k !== 'gw'), p)).toBe(true)
  })

  it('spreads routes that share a corridor', () => {
    const p = new Map<string, Pt>([['a', at(0, 1)], ['b', at(1, 1)], ['c', at(2, 1)]])
    const routes = routeOrthogonal([edge('a', 'c'), { key: 'again', source: 'a', target: 'c', curvature: 0 }], p)
    const [one, two] = [...routes.values()]
    expect(JSON.stringify(one)).not.toEqual(JSON.stringify(two))
  })
})

describe('moving along a route', () => {
  it('goes by length', () => {
    const r = [{ x: 0, y: 0 }, { x: 0, y: 10 }, { x: 30, y: 10 }]
    expect(pointAlong(r, 0)).toEqual({ x: 0, y: 0 })
    expect(pointAlong(r, 0.25)).toEqual({ x: 0, y: 10 })
    expect(pointAlong(r, 1)).toEqual({ x: 30, y: 10 })
  })
})
