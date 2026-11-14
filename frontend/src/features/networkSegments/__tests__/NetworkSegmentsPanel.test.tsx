import { render, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { NetworkSegmentsPanel, leaseText } from '../NetworkSegmentsPanel'

const hq = {
  key: 'vlan:10', label: 'hq.corp.example (VLAN 10)', vlanId: 10, serverMac: '00:1b:21:aa:00:01',
  serverIds: ['192.168.1.1'], routers: ['192.168.1.1'], domains: ['hq.corp.example'], leaseSeconds: [86400],
  cidr: '192.168.1.0/24',
  clients: Array.from({ length: 10 }, (_, i) => ({ ip: `192.168.1.${10 + i}`, mac: `f8:bc:12:10:00:${i}`, hostname: `HQ-${i}` })),
}
const branch = {
  ...hq, key: 'vlan:20', label: 'branch.corp.example (VLAN 20)', vlanId: 20, serverMac: '00:1b:21:bb:00:01',
  domains: ['branch.corp.example'], leaseSeconds: [3600],
  clients: [{ ip: '192.168.1.10', mac: '8c:71:f8:20:00:00', hostname: 'BR-TILL-01' }],
}

describe('NetworkSegmentsPanel (#462)', () => {
  it('shows each network sharing a range, what told them apart, and the addresses on both', async () => {
    server.use(http.get('*/files/f1/network-segments', () => HttpResponse.json({
      segments: [hq, branch],
      overlaps: [{ cidr: '192.168.1.0/24', segmentKeys: ['vlan:10', 'vlan:20'], sharedAddresses: ['192.168.1.1', '192.168.1.10'] }],
    })))
    render(<NetworkSegmentsPanel fileId="f1" />)
    expect(await screen.findByText('2 networks share 192.168.1.0/24')).toBeInTheDocument()
    const cards = screen.getAllByTestId('network-segment')
    expect(cards[0]).toHaveTextContent('hq.corp.example (VLAN 10)')
    expect(cards[0]).toHaveTextContent('00:1b:21:aa:00:01')
    expect(cards[0]).toHaveTextContent('1 day')
    expect(cards[1]).toHaveTextContent('1 h')
    expect(cards[0]).toHaveTextContent('Show all 10') // long client lists are cut
    expect(screen.getByTestId('network-segments-shared')).toHaveTextContent('192.168.1.1, 192.168.1.10')
  })

  it('shows nothing for a capture with one network per range', async () => {
    let called = false
    server.use(http.get('*/files/f2/network-segments', () => {
      called = true
      return HttpResponse.json({ segments: [hq], overlaps: [] })
    }))
    const { container } = render(<NetworkSegmentsPanel fileId="f2" />)
    await waitFor(() => expect(called).toBe(true))
    expect(container).toBeEmptyDOMElement()
  })

  it('words lease times', () => {
    expect(leaseText(86400)).toBe('1 day')
    expect(leaseText(172800)).toBe('2 days')
    expect(leaseText(3600)).toBe('1 h')
    expect(leaseText(90)).toBe('90 s')
  })
})
