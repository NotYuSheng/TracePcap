import { describe, expect, it } from 'vitest'
import { effectAlive, moveNote, windowEffects, APPEAR_MS } from '../trafficParticles'

const s = (to: number, unseen: string[], mode: 'hidden' | 'faint' = 'hidden') => ({
  nodeIds: new Set<string>(),
  [mode === 'hidden' ? 'hiddenNodeIds' : 'faintNodeIds']: new Set(unseen),
  window: { from: 0, to },
})

describe('windowEffects', () => {
  const links = [{ from: '10.0.0.50', to: '10.0.0.73@1700', at: 150, label: 'same device, moved 11:05, renamed A → B' }]

  it('rings the nodes the window just saw for the first time', () => {
    const fx = windowEffects(s(100, ['a', 'b']), s(120, ['b']), [], 5)
    expect(fx).toEqual([{ kind: 'appear', node: 'a', t0: 5 }])
  })

  it('works the same when unseen nodes are faint', () => {
    expect(windowEffects(s(100, ['a'], 'faint'), s(120, [], 'faint'), [], 0)).toHaveLength(1)
  })

  it('animates a move the window crossed', () => {
    const fx = windowEffects(s(100, []), s(200, []), links, 0)
    expect(fx).toEqual([
      { kind: 'move', from: '10.0.0.50', to: '10.0.0.73@1700', note: 'moved → 10.0.0.73, renamed A → B', t0: 0 },
    ])
  })

  it('does nothing for a move outside the crossed span', () => {
    expect(windowEffects(s(150, []), s(200, []), links, 0)).toEqual([])
  })

  it('does nothing going back, or when the window is set or cleared', () => {
    expect(windowEffects(s(200, []), s(100, ['a']), links, 0)).toEqual([])
    expect(windowEffects(null, s(200, []), links, 0)).toEqual([])
    expect(windowEffects(s(100, ['a']), null, links, 0)).toEqual([])
  })

  it('skips appear rings on a jump that reveals a crowd', () => {
    const many = Array.from({ length: 50 }, (_, i) => `n${i}`)
    expect(windowEffects(s(100, many), s(200, []), [], 0)).toEqual([])
  })
})

describe('moveNote / effectAlive', () => {
  it('names the new address without the device-key suffix', () => {
    expect(moveNote('10.0.0.9~site-b', 'same device, moved 10:00')).toBe('moved → 10.0.0.9')
  })
  it('expires an appear ring', () => {
    const e = { kind: 'appear' as const, node: 'a', t0: 0 }
    expect(effectAlive(e, APPEAR_MS - 1)).toBe(true)
    expect(effectAlive(e, APPEAR_MS)).toBe(false)
  })
})
