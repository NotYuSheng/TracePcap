/** Which host the host card opens, by address or by MAC, and what it is told about Monitor. */
import { describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import type { GraphNode } from '@/features/network/types'
import { HostDetailModal } from '../HostDetailModal'

const node = (ip: string, mac: string, isL2 = false) =>
  ({ id: ip, label: ip, data: { ip, mac, isL2 } }) as unknown as GraphNode

const graph = {
  nodes: [node('10.0.0.5', 'aa:bb:cc:00:00:05'), node('aa:bb:cc:00:00:09', 'aa:bb:cc:00:00:09', true)],
  hiddenNodesList: [
    node('10.0.0.7', 'aa:bb:cc:00:00:07'),
    // An outside host seen through the router: it carries the router's MAC.
    node('203.0.113.1', 'aa:bb:cc:00:00:01'),
    node('10.0.0.1', 'aa:bb:cc:00:00:01'),
  ],
  edges: [],
  crossEdges: [],
  loading: false,
}
vi.mock('@/features/network/hooks/useNetworkData', () => ({ useNetworkData: () => graph }))

// Stand in for the modal: record what it was asked to show.
const shown: Record<string, unknown>[] = []
vi.mock('../EntityDetailModal', () => ({
  EntityDetailModal: (props: Record<string, unknown>) => {
    shown.push(props)
    return null
  },
}))

const open = (props: Partial<Parameters<typeof HostDetailModal>[0]>) => {
  shown.length = 0
  render(
    <MemoryRouter>
      <HostDetailModal fileId="f" onClose={() => {}} {...props} />
    </MemoryRouter>
  )
  return shown[shown.length - 1]
}

describe('HostDetailModal', () => {
  it('finds a host by address, hidden ones too, and opens its graph card', () => {
    const p = open({ ip: '10.0.0.7' })
    expect((p.graphNode as GraphNode).data.ip).toBe('10.0.0.7')
    expect(p.entityType).toBe('IP')
  })

  it('finds a device by its MAC, keeping it a device so its notes and history are the MAC\'s', () => {
    const p = open({ mac: 'AA:BB:CC:00:00:05', monitor: { isActive: false, lastSeenFileName: 'week2.pcap' } })
    expect((p.graphNode as GraphNode).data.ip).toBe('10.0.0.5')
    expect(p).toMatchObject({ entityType: 'DEVICE', entityKey: 'AA:BB:CC:00:00:05', isActive: false, lastSeenFileName: 'week2.pcap' })
  })

  it('opens a router by its own local address, not an outside host its MAC carried', () => {
    expect((open({ mac: 'aa:bb:cc:00:00:01' }).graphNode as GraphNode).data.ip).toBe('10.0.0.1')
  })

  it('opens a device on the address it was classified with, still as the MAC\'s', () => {
    const p = open({ mac: 'aa:bb:cc:00:00:01', ip: '203.0.113.1' })
    expect((p.graphNode as GraphNode).data.ip).toBe('203.0.113.1')
    expect(p).toMatchObject({ entityType: 'DEVICE', entityKey: 'aa:bb:cc:00:00:01' })
  })

  it('opens a layer-2-only device on its MAC node', () => {
    expect((open({ mac: 'aa:bb:cc:00:00:09' }).graphNode as GraphNode).data.isL2).toBe(true)
  })

  it('falls back to the plain detail when the host is not on the graph', () => {
    const p = open({ ip: '192.0.2.1', monitor: { isActive: true } })
    expect(p.graphNode).toBeUndefined()
    expect(p).toMatchObject({ entityType: 'IP', entityKey: '192.0.2.1', isActive: true })
  })
})
