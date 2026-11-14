/**
 * buildNetworkGraph turns conversations into the graph an analyst reads. It is the largest
 * function in the frontend and had no tests, so these cover its observable contracts — node and
 * edge construction, the caps that keep a big capture renderable, and the seeding that makes the
 * node count agree with the analysis summary — rather than every internal branch.
 */
import { describe, expect, it } from 'vitest'

import type { Conversation } from '@/types'
import { buildNetworkGraph } from '../networkService'

function conversation(src: string, dst: string, overrides: Partial<Conversation> = {}): Conversation {
  return {
    id: `${src}->${dst}`,
    endpoints: [
      { ip: src, port: 1234 },
      { ip: dst, port: 443 },
    ],
    protocol: { name: 'TCP', layer: 'transport' },
    packetCount: 10,
    totalBytes: 1000,
    startTime: 0,
    endTime: 1,
    flowRisks: [],
    customSignatures: [],
    suricataAlerts: [],
    ...overrides,
  } as unknown as Conversation
}

describe('buildNetworkGraph', () => {
  it('creates one node per distinct host and one edge per conversation', () => {
    const result = buildNetworkGraph([conversation('10.0.0.1', '8.8.8.8')])

    expect(result.nodes.map(n => n.id).sort()).toEqual(['10.0.0.1', '8.8.8.8'])
    expect(result.edges).toHaveLength(1)
  })

  it('reuses a node when a host appears in several conversations', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8'),
      conversation('10.0.0.1', '1.1.1.1'),
    ])

    // Three hosts, not four: the shared host must be one node or the graph double-counts it.
    expect(result.nodes).toHaveLength(3)
    expect(result.edges).toHaveLength(2)
  })

  it('accumulates traffic onto the shared node rather than overwriting it', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', { packetCount: 10, totalBytes: 1000 }),
      conversation('10.0.0.1', '1.1.1.1', { packetCount: 5, totalBytes: 500 }),
    ])

    const shared = result.nodes.find(n => n.id === '10.0.0.1')!
    // Node size and ranking are driven by these totals, so overwriting would shrink a busy host.
    expect(shared.data.bytesSent).toBe(1500)
  })

  it('caps the conversations it will render', () => {
    const many = Array.from({ length: 10 }, (_, i) => conversation('10.0.0.1', `8.8.8.${i}`))

    const result = buildNetworkGraph(many, undefined, 3)

    // The cap exists so a 100k-conversation capture still renders; without it the browser hangs.
    expect(result.edges).toHaveLength(3)
  })

  it('reports statistics consistent with the graph it built', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', { packetCount: 10 }),
      conversation('10.0.0.2', '1.1.1.1', { packetCount: 5 }),
    ])

    expect(result.stats.totalNodes).toBe(result.nodes.length)
    expect(result.stats.totalEdges).toBe(result.edges.length)
  })

  it('breaks packet counts down by protocol', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', {
        protocol: { name: 'TCP', layer: 'transport' },
        packetCount: 10,
      } as Partial<Conversation>),
      conversation('10.0.0.2', '1.1.1.1', {
        protocol: { name: 'UDP', layer: 'transport' },
        packetCount: 4,
      } as Partial<Conversation>),
    ])

    expect(result.stats.protocolBreakdown).toMatchObject({ TCP: 10, UDP: 4 })
  })

  it('marks an edge as risky when the conversation carries flow risks', () => {
    const result = buildNetworkGraph([
      conversation('10.0.0.1', '8.8.8.8', {
        flowRisks: ['Self-signed certificate'],
      } as Partial<Conversation>),
    ])

    // selectSignificantNodes reads hasRisks to decide visibility, so this flag is what keeps a
    // flagged host on screen when the graph is capped.
    expect(result.edges[0].data.hasRisks).toBe(true)
  })

  it('returns an empty graph for no conversations rather than throwing', () => {
    const result = buildNetworkGraph([])

    expect(result.nodes).toEqual([])
    expect(result.edges).toEqual([])
    expect(result.stats.totalNodes).toBe(0)
  })
})

describe('buildNetworkGraph: an address more than one device held (#918 slice 2)', () => {
  // 10.0.0.50 is a laptop until 11:00, then a phone. Times are wall-clock arrays, as the API sends.
  const boundary = [2026, 11, 10, 11, 0, 0]
  const before = new Date(2026, 10, 10, 10, 30, 0).getTime()
  const after = new Date(2026, 10, 10, 11, 30, 0).getTime()
  const reused = [
    {
      ip: '10.0.0.50',
      occupancies: [
        {
          idx: 0, mac: 'f8:bc:12:00:00:01', hostname: 'LAPTOP-ALICE', endsAt: boundary, automatic: false, conversations: 1,
          classification: { deviceType: 'LAPTOP_DESKTOP', confidence: 100, manufacturer: 'Dell Inc.', ttl: 128 },
        },
        {
          idx: 1, mac: '8c:71:f8:00:00:02', hostname: 'Galaxy-S24', startsAt: boundary, automatic: true, conversations: 1,
          classification: { deviceType: 'MOBILE', confidence: 67, manufacturer: 'Samsung Electronics Co.,Ltd', ttl: 64 },
        },
      ],
    },
  ]
  const convs = () => [
    conversation('10.0.0.50', '52.97.1.10', { id: 'laptop-mail', startTime: before }),
    conversation('10.0.0.50', '185.220.101.77', { id: 'phone-beacon', startTime: after }),
  ]
  const addressRow = [{ ip: '10.0.0.50', deviceType: 'LAPTOP_DESKTOP', confidence: 100, hostname: 'LAPTOP-ALICE', mac: 'f8:bc:12:00:00:01' }]

  it('draws one node per device, and puts each conversation on the device that held the address then', () => {
    const g = buildNetworkGraph(convs(), undefined, 500, addressRow as never, 0, undefined, undefined, reused as never)

    const ids = g.nodes.map(n => n.id).sort()
    expect(ids).toEqual(['10.0.0.50@0', '10.0.0.50@1', '185.220.101.77', '52.97.1.10'])
    expect(g.edges.find(e => e.id === 'laptop-mail')!.source).toBe('10.0.0.50@0')
    // The beacon is the phone's, not the laptop's: the whole point of splitting.
    expect(g.edges.find(e => e.id === 'phone-beacon')!.source).toBe('10.0.0.50@1')
  })

  it("gives each device its own name, MAC and classification, not the address's blend", () => {
    const g = buildNetworkGraph(convs(), undefined, 500, addressRow as never, 0, undefined, undefined, reused as never)
    const phone = g.nodes.find(n => n.id === '10.0.0.50@1')!

    expect(phone.label).toBe('Galaxy-S24')
    expect(phone.data.ip).toBe('10.0.0.50')
    expect(phone.data.mac).toBe('8c:71:f8:00:00:02')
    expect(phone.data.deviceType).toBe('MOBILE')
    expect(phone.data.identityLabel).toBe('MOBILE')
    expect(phone.data.ttl).toBe(64)
    expect(phone.data.occupancy).toMatchObject({ idx: 1, of: 2 })
  })

  it('keeps one node keyed by IP for an address one device held', () => {
    const g = buildNetworkGraph(convs(), undefined, 500, addressRow as never, 0, undefined, undefined, [])
    expect(g.nodes.filter(n => n.data.ip === '10.0.0.50').map(n => n.id)).toEqual(['10.0.0.50'])
  })

  it("shows an analyst's label and role on the one device they're on (#918 slice 3)", () => {
    const phoneKey = '10.0.0.50@2026-11-10T11:00:00'
    const withKeys = [
      {
        ...reused[0],
        occupancies: reused[0].occupancies.map(o =>
          o.startsAt ? { ...o, boundaryKey: '2026-11-10T11:00:00' } : o,
        ),
      },
    ]
    const identities = [
      { ip: '10.0.0.50', primaryLabel: 'LAPTOP_DESKTOP', basis: 'MACHINE', confidence: 100, contested: false },
      { ip: phoneKey, primaryLabel: 'IOT', basis: 'HUMAN', confidence: 100, contested: false },
    ]
    const roles = [{ entityType: 'IP', entityKey: phoneKey, roleLabel: 'Visitor phone' }]
    const g = buildNetworkGraph(convs(), undefined, 500, addressRow as never, 0, identities as never, roles as never, withKeys as never)
    const laptop = g.nodes.find(n => n.id === '10.0.0.50@0')!
    const phone = g.nodes.find(n => n.id === '10.0.0.50@1')!

    expect(phone.data.occupancy?.key).toBe(phoneKey)
    expect(laptop.data.occupancy?.key).toBe('10.0.0.50')
    expect(phone.data.identityLabel).toBe('IOT')
    expect(phone.data.identityBasis).toBe('HUMAN')
    expect(phone.data.roleLabel).toBe('Visitor phone')
    expect(laptop.data.identityLabel).toBe('LAPTOP_DESKTOP')
    expect(laptop.data.roleLabel).toBeUndefined()
  })
})
