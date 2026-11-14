import { describe, expect, it } from 'vitest'
import type { GraphNode } from '../../types'
import { linkMovedDevices } from '../networkService'

const node = (id: string, ip: string, occupancyKey?: string) =>
  ({ id, label: id, data: { ip, occupancy: occupancyKey ? { idx: 0, of: 2, key: occupancyKey } : undefined } }) as unknown as GraphNode

describe('linkMovedDevices', () => {
  const move = {
    mac: 'f8:bc:12:00:00:01', fromIp: '10.0.0.50', fromKey: '10.0.0.50', fromHostname: 'LAPTOP-ALICE',
    toIp: '10.0.0.73', toKey: '10.0.0.73', toHostname: 'ALICE-WS01',
    arrived: [2026, 11, 10, 11, 5, 1], evidence: 'DHCP lease',
  }

  it("links the moved device's two nodes, finding a shared address's node by its device key", () => {
    // 10.0.0.50 was shared, so the laptop's node there is 10.0.0.50@0 with the bare key.
    const nodes = [node('10.0.0.50@0', '10.0.0.50', '10.0.0.50'), node('10.0.0.50@1', '10.0.0.50', '10.0.0.50@x'), node('10.0.0.73', '10.0.0.73')]
    const links = linkMovedDevices(nodes, [move])
    expect(links).toHaveLength(1)
    expect(links[0]).toMatchObject({ from: '10.0.0.50@0', to: '10.0.0.73' })
    expect(links[0].label).toContain('renamed LAPTOP-ALICE → ALICE-WS01')
    expect(nodes[0].data.moves?.[0]).toMatchObject({ ip: '10.0.0.73', direction: 'to' })
    expect(nodes[2].data.moves?.[0]).toMatchObject({ ip: '10.0.0.50', direction: 'from', hostname: 'LAPTOP-ALICE' })
    expect(nodes[1].data.moves).toBeUndefined() // the phone didn't move
  })

  it('notes the move on a shown node even when the other end is hidden', () => {
    const nodes = [node('10.0.0.73', '10.0.0.73')]
    expect(linkMovedDevices(nodes, [move])).toHaveLength(0)
    expect(nodes[0].data.moves).toHaveLength(1)
  })
})
