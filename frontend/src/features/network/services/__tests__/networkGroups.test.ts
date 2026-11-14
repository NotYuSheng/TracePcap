import { describe, expect, it } from 'vitest'
import type { GraphNode } from '../../types'
import type { NetworkSegment } from '@/features/networkSegments/networkSegmentService'
import { allGroups, buildGroupTree, dnsNamesByIp, domainOf, layoutGroups, leafGroups, subnetOf, type GroupNode } from '../networkGroups'

const node = (id: string, data: Partial<GraphNode['data']> = {}): GraphNode =>
  ({ id, label: id, data: { ip: id.split(/[@~]/)[0], deviceType: 'LAPTOP_DESKTOP', ...data } }) as unknown as GraphNode

const seg = (key: string, label: string, clients: [string, string][], net = '192.168.1'): NetworkSegment => ({
  key, label, serverIds: [`${net}.1`], routers: [`${net}.1`], domains: [], leaseSeconds: [],
  cidr: `${net}.0/24`, serverMac: '00:1b:21:c0:00:01', clients: clients.map(([ip, mac]) => ({ ip, mac })),
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
    expect(net.children[0].children.map(g => g.label)).toEqual(['Laptops and desktops', 'Printer'])
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

  it('a router serving several VLANs with one MAC: each interface in its own network', () => {
    const segments = [
      seg('vlan:10', 'Staff', [['10.20.10.21', 'aa:00:00:00:00:01']], '10.20.10'),
      seg('vlan:30', 'Devices', [['10.20.30.31', 'bb:00:00:00:00:01']], '10.20.30'),
    ]
    const router = { mac: '00:1b:21:c0:00:01' }
    const tree = buildGroupTree([node('10.20.10.1', router), node('10.20.30.1', router)], { segments })
    expect(find(tree, 'network:vlan:10')?.children[0].label).toBe('10.20.10.0/24')
    expect(find(tree, 'network:vlan:30')?.children[0].label).toBe('10.20.30.0/24')
  })

  it('an internet host with no hostname takes the name it was looked up by', () => {
    const dnsNames = dnsNamesByIp([
      { entries: [
        { queryName: 'api.github.com.', resolvedIps: ['140.82.112.6'], queryCount: 3 },
        { queryName: 'cdn.other.net', resolvedIps: ['140.82.112.6'], queryCount: 1 },
        { queryName: 'www.google.com', resolvedIps: ['142.250.4.100'], queryCount: 2 },
      ] },
    ])
    expect(dnsNames.get('140.82.112.6')).toBe('api.github.com')
    const tree = buildGroupTree([node('140.82.112.6'), node('142.250.4.100'), node('8.8.4.4')], { dnsNames })
    expect(tree[0].children.map(g => g.label)).toEqual(['github.com', 'google.com', 'No hostname'])
  })

  it('a static host joins the one network whose range holds it, not when ranges overlap', () => {
    const one = [seg('vlan:10', 'HQ', [['192.168.10.21', 'aa:00:00:00:00:01']], '192.168.10')]
    expect(find(buildGroupTree([node('192.168.10.10')], { segments: one }), 'network:vlan:10')).toBeDefined()
    const two = [
      seg('vlan:10', 'HQ', [['192.168.1.21', 'aa:00:00:00:00:01']]),
      seg('vlan:20', 'Branch', [['192.168.1.22', 'bb:00:00:00:00:01']]),
    ]
    expect(buildGroupTree([node('192.168.1.10')], { segments: two })[0].children[0].label).toBe('Other local addresses')
  })

  it('groups device types by family: a DNS server and a server are both servers', () => {
    const tree = buildGroupTree([
      node('10.0.0.53', { deviceType: 'DNS_SERVER' }),
      node('10.0.0.10', { deviceType: 'SERVER' }),
      node('10.0.0.80', { deviceType: 'WEB_SERVER' }),
      node('10.0.0.21', { deviceType: 'MOBILE' }),
    ])
    const types = tree[0].children[0].children[0].children
    expect(types.map(g => [g.label, g.nodeIds.length])).toEqual([['Phones and tablets', 1], ['Servers', 3]])
  })

  it("the analyst's moves: a device goes to the group it was put in; an emptied group goes", () => {
    const nodes = [node('10.0.0.5'), node('10.0.0.53', { deviceType: 'DNS_SERVER' }), node('10.0.0.6')]
    const auto = leafGroups(buildGroupTree(nodes))
    const servers = [...auto.values()].find(g => g.label === 'Servers')!
    const laptops = [...auto.values()].find(g => g.label === 'Laptops and desktops')!
    const tree = buildGroupTree(nodes, { placements: { '10.0.0.5': servers.id, '10.0.0.6': servers.id } })
    const leaves = leafGroups(tree)
    expect(leaves.get(servers.id)?.nodeIds).toEqual(['10.0.0.53', '10.0.0.5', '10.0.0.6'])
    expect(leaves.get(servers.id)?.movedIds).toEqual(['10.0.0.5', '10.0.0.6'])
    expect(leaves.has(laptops.id)).toBe(false)
    const box = layoutGroups(tree).boxes.find(b => b.id === servers.id)!
    expect(box.leaf).toBe(true)
    expect(box.moved).toBe(2)
  })

  it('a move to a group no longer on the map is skipped', () => {
    const nodes = [node('10.0.0.5')]
    const tree = buildGroupTree(nodes, { placements: { '10.0.0.5': 'type:gone:10.9.9.0/24:Servers', '10.9.9.9': 'x' } })
    expect([...leafGroups(tree).values()].map(g => g.nodeIds)).toEqual([['10.0.0.5']])
  })

  it("the analyst's own groups: inside their parent, kept when empty, devices can be moved in", () => {
    const nodes = [node('10.0.0.5'), node('10.0.0.6')]
    const net = buildGroupTree(nodes)[0].children[0]
    const mine = { id: 'user:a1', name: 'Payments', parentId: net.id }
    const empty = buildGroupTree(nodes, { userGroups: [mine] })
    const g = allGroups(empty).get('user:a1')!
    expect(g).toMatchObject({ kind: 'user', label: 'Payments', level: net.level + 1, nodeIds: [] })
    expect(layoutGroups(empty).boxes.find(b => b.id === 'user:a1')).toMatchObject({ leaf: true, count: 0 })
    const moved = buildGroupTree(nodes, { userGroups: [mine], placements: { '10.0.0.5': 'user:a1' } })
    expect(allGroups(moved).get('user:a1')!.nodeIds).toEqual(['10.0.0.5'])
  })

  it('a group of your own inside a box of devices is skipped (boxes hold groups or devices)', () => {
    const nodes = [node('10.0.0.5')]
    const leaf = [...leafGroups(buildGroupTree(nodes)).values()][0]
    const tree = buildGroupTree(nodes, { userGroups: [{ id: 'user:x', name: 'X', parentId: leaf.id }] })
    expect(allGroups(tree).has('user:x')).toBe(false)
  })

  it('names and notes: a renamed group keeps its automatic name; the note goes on the box', () => {
    const nodes = [node('10.0.0.5')]
    const tree = buildGroupTree(nodes, { names: { local: 'Head office' }, notes: { local: 'Floor 3' } })
    expect(tree[0]).toMatchObject({ label: 'Head office', autoLabel: 'Your networks', note: 'Floor 3' })
    const box = layoutGroups(tree).boxes.find(b => b.id === 'local')!
    expect(box.note).toBe('Floor 3')
    expect(box.header).toBeGreaterThan(layoutGroups(buildGroupTree(nodes)).boxes.find(b => b.id === 'local')!.header)
  })
})
