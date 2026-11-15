import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { HostOccupancySection } from '../HostOccupancySection'
import { toInputValue } from '@/features/occupancy/occupancyService'

const reused = {
  ip: '10.0.0.50',
  firstActivity: [2024, 10, 27, 3, 33, 20],
  lastActivity: [2024, 10, 27, 4, 33, 21],
  overlapping: false,
  virtualAddress: false,
  canEdit: true,
  decisions: [],
  suggestions: [],
  occupancies: [
    { idx: 0, mac: 'bb:bb:bb:00:00:01', hostname: 'LAPTOP-ALICE', endsAt: [2024, 10, 27, 4, 33, 20], automatic: false, conversations: 2 },
    {
      idx: 1, mac: 'cc:cc:cc:00:00:02', hostname: 'iPhone-Bob', startsAt: [2024, 10, 27, 4, 33, 20],
      startSource: 'arp', startEvidence: 'ARP: bb:bb:bb:00:00:01 last seen …, then cc:cc:cc:00:00:02 from …',
      boundaryKey: '2024-10-27T04:33:20', automatic: true, conversations: 1,
    },
  ],
}

const single = {
  ...reused,
  ip: '10.0.0.70',
  occupancies: [{ idx: 0, mac: 'ee:ee:ee:00:00:09', automatic: false, conversations: 4 }],
  suggestions: [{ at: [2024, 10, 27, 3, 50, 0], key: '2024-10-27T03:50', kind: 'silence', description: 'No traffic for 15 min before this' }],
}

describe('HostOccupancySection (#918 item 3)', () => {
  it('says an address used on two networks is a machine on each, not one device (#462)', async () => {
    server.use(http.get('*/files/f1/hosts/:ip/occupancies', () =>
      HttpResponse.json({ ...single, suggestions: [], networks: ['hq.corp.example', 'branch.corp.example'] })))
    render(<HostOccupancySection fileId="f1" ip="192.168.1.10" />)
    expect(await screen.findByText(/A different machine on each of 2 networks/)).toHaveTextContent('hq.corp.example, branch.corp.example')
    expect(screen.queryByText('One device for the whole capture.')).not.toBeInTheDocument()
  })


  it('picks another device by its key: the bare IP for the first, ip@start for a later one', async () => {
    const picked: string[] = []
    server.use(http.get('*/files/f1/hosts/:ip/occupancies', () => HttpResponse.json(reused)))
    const user = userEvent.setup()
    const { rerender } = render(
      <HostOccupancySection fileId="f1" ip="10.0.0.50" focusIdx={0} focusLabel="showing" onSelect={(_, k) => picked.push(k)} />,
    )
    const show = await screen.findAllByRole('button', { name: 'Show this device' })
    expect(show).toHaveLength(1) // not on the device already showing
    await user.click(show[0])
    expect(picked).toEqual(['10.0.0.50@2024-10-27T04:33:20'])
    rerender(<HostOccupancySection fileId="f1" ip="10.0.0.50" focusIdx={1} focusLabel="showing" onSelect={(_, k) => picked.push(k)} />)
    await user.click(await screen.findByRole('button', { name: 'Show this device' }))
    expect(picked[1]).toBe('10.0.0.50')
  })


  it("shows each device's own classification, and marks the device a graph node stands for", async () => {
    const classified = {
      ...reused,
      occupancies: [
        { ...reused.occupancies[0], classification: { deviceType: 'LAPTOP_DESKTOP', confidence: 100, manufacturer: 'Dell Inc.', ttl: 128 } },
        { ...reused.occupancies[1], classification: { deviceType: 'MOBILE', confidence: 67, ttl: 64 } },
      ],
    }
    server.use(http.get('*/files/f1/hosts/:ip/occupancies', () => HttpResponse.json(classified)))
    render(<HostOccupancySection fileId="f1" ip="10.0.0.50" focusIdx={1} />)
    const verdicts = await screen.findAllByTestId('occupancy-verdict')
    expect(verdicts[0]).toHaveTextContent('100% · Dell Inc. · TTL 128')
    expect(verdicts[1]).toHaveTextContent('67% · TTL 64')
    const rows = screen.getAllByTestId('occupancy-row')
    expect(rows[1]).toContainElement(screen.getByTestId('occupancy-this-node'))
    expect(rows[0]).not.toHaveTextContent('this node')
  })


  it('shows each device on a reused address with its evidence', async () => {
    server.use(http.get('*/files/f1/hosts/:ip/occupancies', () => HttpResponse.json(reused)))
    render(<HostOccupancySection fileId="f1" ip="10.0.0.50" />)
    const rows = await screen.findAllByTestId('occupancy-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('LAPTOP-ALICE')
    expect(rows[0]).toHaveTextContent('2 conversations')
    expect(rows[1]).toHaveTextContent('iPhone-Bob')
    expect(rows[1]).toHaveTextContent('ARP: bb:bb:bb:00:00:01')
    expect(screen.getByText('Devices on this address (2)')).toBeInTheDocument()
  })

  it('merges an automatic split, sending its exact boundary and the reason', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.get('*/files/f1/hosts/:ip/occupancies', () => HttpResponse.json(reused)),
      http.post('*/files/f1/hosts/:ip/occupancy-decisions', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ ...reused, occupancies: [reused.occupancies[0]], decisions: [{ id: 7, at: [2024, 10, 27, 4, 33, 20], action: 'merge', reason: 'MAC rotation', actor: 'system' }] }, { status: 201 })
      })
    )
    const user = userEvent.setup()
    render(<HostOccupancySection fileId="f1" ip="10.0.0.50" />)
    await user.click(await screen.findByRole('button', { name: 'Not a different device?' }))
    const merge = await screen.findByRole('button', { name: 'Merge' })
    expect(merge).toBeDisabled() // a reason is required
    await user.type(screen.getByLabelText('Why (kept with the merge)'), 'MAC rotation')
    await user.click(merge)
    await waitFor(() => expect(body).toEqual({ at: '2024-10-27T04:33:20', action: 'merge', reason: 'MAC rotation' }))
    expect(await screen.findByTestId('occupancy-decisions')).toHaveTextContent('Merged at')
    expect(screen.getByRole('button', { name: 'Undo' })).toBeInTheDocument()
  })

  it('splits a single-device address at a suggested point', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.get('*/files/f1/hosts/:ip/occupancies', () => HttpResponse.json(single)),
      http.post('*/files/f1/hosts/:ip/occupancy-decisions', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json(reused, { status: 201 })
      })
    )
    const user = userEvent.setup()
    render(<HostOccupancySection fileId="f1" ip="10.0.0.70" />)
    expect(await screen.findByText(/One device for the whole capture/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /Split by time/ }))
    // The first suggestion is picked by default.
    expect(await screen.findByLabelText(/No traffic for 15 min/)).toBeChecked()
    await user.type(screen.getByLabelText('Why (kept with the split)'), 'cloned VMs')
    await user.click(screen.getByRole('button', { name: 'Split' }))
    await waitFor(() => expect(body).toEqual({ at: '2024-10-27T03:50', action: 'split', reason: 'cloned VMs' }))
    expect(await screen.findAllByTestId('occupancy-row')).toHaveLength(2)
  })

  it('undoes a decision', async () => {
    let deleted = false
    const withDecision = { ...single, decisions: [{ id: 3, at: [2024, 10, 27, 3, 50, 0], action: 'split', reason: 'cloned', actor: 'alice' }] }
    server.use(
      http.get('*/files/f1/hosts/:ip/occupancies', () => HttpResponse.json(deleted ? single : withDecision)),
      http.delete('*/files/f1/hosts/:ip/occupancy-decisions/3', () => {
        deleted = true
        return new HttpResponse(null, { status: 204 })
      })
    )
    const user = userEvent.setup()
    render(<HostOccupancySection fileId="f1" ip="10.0.0.70" />)
    expect(await screen.findByTestId('occupancy-decisions')).toHaveTextContent('by alice: cloned')
    await user.click(screen.getByRole('button', { name: 'Undo' }))
    await waitFor(() => expect(screen.queryByTestId('occupancy-decisions')).not.toBeInTheDocument())
  })

  it('says why editing is off, and hides itself for a failover address', async () => {
    server.use(
      http.get('*/files/f1/hosts/:ip/occupancies', ({ params }) =>
        HttpResponse.json(
          params.ip === '10.0.0.254'
            ? { ...single, ip: '10.0.0.254', virtualAddress: true, suggestions: [] }
            : { ...single, canEdit: false, editReason: 'Only admins can split or merge hosts.' }
        )
      )
    )
    const { unmount } = render(<HostOccupancySection fileId="f1" ip="10.0.0.70" />)
    expect(await screen.findByRole('button', { name: /Split by time/ })).toBeDisabled()
    expect(screen.getByText('Only admins can split or merge hosts.')).toBeInTheDocument()
    unmount()
    render(<HostOccupancySection fileId="f1" ip="10.0.0.254" />)
    await waitFor(() => expect(screen.queryByTestId('host-occupancy')).not.toBeInTheDocument())
  })

  it('formats an API date for a datetime-local input', () => {
    expect(toInputValue([2024, 1, 2, 3, 4, 5, 6000000])).toBe('2024-01-02T03:04:05')
    expect(toInputValue('2024-01-02T03:04:05.123')).toBe('2024-01-02T03:04:05')
    expect(toInputValue(null)).toBe('')
  })
})
