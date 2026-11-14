import { describe, expect, it } from 'vitest'
import type { GraphNode } from '../../types'
import type { NetworkSegment } from '@/features/networkSegments/networkSegmentService'
import { buildGroupTree, domainOf, layoutGroups, subnetOf, type GroupNode } from '../networkGroups'

const node = (id: string, data: Partial<GraphNode['data']> = {}): GraphNode =>
  ({ id, label: id, data: { ip: id.split(/[@~]/)[0], deviceType: 'LAPTOP_DESKTOP', ...data } }) as unknown as GraphNode

const seg = (key: string, label: string, clients: [string, string][]): NetworkSegment => ({
  key, label, serverIds: ['192.168.1.1'], routers: ['192.168.1.1'], domains: [], leaseSeconds: [],
  cidr: '192.168.1.0/24', clients: clients.map(([ip, mac]) => ({ ip, mac })),
})

const find = (gs: GroupNode[], id: string): GroupNode | undefined => {
  for (const g of gs) {
    if (g.id === id) return g
    const f = find(g.children, id)
    if (f) return f
  }
}

describe('networkGroups', () => {
  it('splits local, internet and broadcast; nests network ▸ subnet ▸ device type', () => {
    const tree = buildGroupTree([
      node('192.168.1.10', { mac: 'aa:00:00:00:00:01' }),
      node('192.168.1.12', { mac: 'aa:00:00:00:00:02', deviceType: 'PRINTER' }),
      node('93.184.216.34', { hostname: 'www.example.com' }),
      node('255.255.255.255'),
    ])
    expect(tree.map(g => g.label)).toEqual(['Your networks', 'Internet', 'Broadcast and multicast'])
    const net = tree[0].children[0]
    expect(net.label).toBe('Local network')
    expect(net.children[0].label).toBe('192.168.1.0/24')
    expect(net.children[0].children.map(g => g.label)).toEqual(['Laptop / Desktop', 'Printer'])
    expect(find(tree, 'domain:example.com')?.nodeIds).toEqual(['93.184.216.34'])
  })

  it('puts overlapping networks apart: by the device key, else the MAC', () => {
    const segments = [
      seg('vlan:10', 'HQ', [['192.168.1.10', 'aa:00:00:00:00:01']]),
      seg('vlan:20', 'Branch', [['192.168.1.10', 'bb:00:00:00:00:01']]),
    ]
    const tree = buildGroupTree(
      [node('192.168.1.10', { mac: 'aa:00:00:00:00:01' }), node('192.168.1.10~vlan:20', { mac: 'bb:00:00:00:00:01' })],
      { segments },
    )
    const nets = tree[0].children
    expect(nets.map(n => n.label)).toEqual(['Branch', 'HQ'])
    expect(find(tree, 'network:vlan:20')?.children[0].children[0].nodeIds).toEqual(['192.168.1.10~vlan:20'])
    expect(find(tree, 'network:vlan:10')?.detail).toContain('gateway 192.168.1.1')
  })

  it('a custom private range counts as local', () => {
    const tree = buildGroupTree([node('100.64.0.3')], {
      customRanges: [{ id: 1, cidr: '100.64.0.0/10', classification: 'PRIVATE' } as never],
    })
    expect(tree[0].label).toBe('Your networks')
  })

  it('lays every device inside its box, and every box inside its parent', () => {
    const nodes = Array.from({ length: 9 }, (_, i) => node(`10.0.${i % 2}.${i + 1}`))
    const { positions, boxes } = layoutGroups(buildGroupTree(nodes))
    expect(positions.size).toBe(9)
    const byId = new Map(boxes.map(b => [b.id, b]))
    for (const n of nodes) {
      const p = positions.get(n.id)!
      const inner = boxes.filter(b => b.memberIds.includes(n.id))
      for (const b of inner) {
        expect(p.x).toBeGreaterThan(b.x)
        expect(p.x).toBeLessThan(b.x + b.w)
        expect(p.y).toBeGreaterThan(b.y)
        expect(p.y).toBeLessThan(b.y + b.h)
      }
    }
    expect(byId.get('local')!.count).toBe(9)
  })

  it('subnets and domains', () => {
    expect(subnetOf('10.1.2.3')).toBe('10.1.2.0/24')
    expect(subnetOf('2001:db8:1:2::5')).toBe('2001:db8:1:2::/64')
    expect(domainOf('cdn.example.co.uk')).toBe('example.co.uk')
    expect(domainOf('www.google.com')).toBe('google.com')
  })
})
