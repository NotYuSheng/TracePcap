import { describe, expect, it } from 'vitest'
import { describeMoment, describePacket, flightsFor, groupMoments, localIso, momentIndexOf, type ReplayPacket } from '../packetReplay'

const p = (number: number, t: number, extra: Partial<ReplayPacket> = {}): ReplayPacket => ({
  number, t, srcIp: '10.0.0.1', dstIp: '10.0.0.2', protocol: 'TCP', conversationId: 'c1', ...extra,
})

describe('packetReplay', () => {
  it('packets at the same instant are one moment; the next instant is the next', () => {
    const ms = groupMoments([p(1, 1000), p(2, 1000.4, { dstIp: '224.0.0.251' }), p(3, 1001), p(4, 1005)])
    expect(ms.map(m => m.packets.map(x => x.number))).toEqual([[1, 2, 3], [4]])
  })

  it('finds the moment holding a packet', () => {
    const ms = groupMoments([p(1, 0), p(2, 0), p(3, 10), p(4, 20), p(5, 20)])
    expect(momentIndexOf(ms, 1)).toBe(0)
    expect(momentIndexOf(ms, 2)).toBe(0)
    expect(momentIndexOf(ms, 3)).toBe(1)
    expect(momentIndexOf(ms, 5)).toBe(2)
  })

  it('a packet flies along its conversation, the way it went; undrawn conversations fly nowhere', () => {
    const ends = new Map([['c1', { source: 'A', target: 'B', sourceIp: '10.0.0.1' }]])
    const m = groupMoments([
      p(1, 0),
      p(2, 0, { srcIp: '10.0.0.2', dstIp: '10.0.0.1' }),
      p(3, 0, { conversationId: 'filtered-out' }),
    ])[0]
    expect(flightsFor(m, ends)).toEqual([
      { from: 'A', to: 'B', protocol: 'TCP' },
      { from: 'B', to: 'A', protocol: 'TCP' },
    ])
  })

  it('describes packets and moments', () => {
    expect(describePacket(p(1, 0, { srcPort: 51334, dstPort: 445, size: 74, info: '[SYN]' }))).toBe(
      'TCP 10.0.0.1:51334 → 10.0.0.2:445 · 74 B · [SYN]',
    )
    const m = groupMoments([p(1, 0, { protocol: 'DNS' }), p(2, 0, { protocol: 'DNS' }), p(3, 0, { protocol: 'ARP' })])[0]
    expect(describeMoment(m)).toBe('3 packets at once: DNS ×2, ARP')
  })

  it('local ISO round-trips through Date', () => {
    const ms = new Date(2026, 10, 14, 9, 5, 3, 7).getTime()
    expect(localIso(ms)).toBe('2026-11-14T09:05:03.007')
    expect(new Date(localIso(ms)).getTime()).toBe(ms)
  })
})
