import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { NetworkDevicesModal } from '../NetworkDevicesModal'
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types'

const snapshots = [1, 2, 3].map(n => ({ id: `s${n}`, fileId: `f${n}`, fileName: `week${n}.pcap`, snapshotOrder: n })) as unknown as NetworkSnapshot[]

const laptop = {
  mac: 'f8:bc:12:00:00:01', macs: ['f8:bc:12:00:00:01'], links: [], name: 'LAPTOP-ALICE', deviceType: 'LAPTOP_DESKTOP', vendor: 'Dell Inc.', macKind: 'HARDWARE',
  label: "Alice's laptop", addresses: [{ ip: '10.0.0.50', firstSnapshot: 1, lastSnapshot: 2 }, { ip: '10.0.0.73', firstSnapshot: 3, lastSnapshot: 3 }],
  seenInFileIds: ['f1', 'f2', 'f3'], lastFileId: 'f3', lastKey: '10.0.0.73', flags: [],
}
const clone = {
  mac: '00:50:56:a1:3c:09', macs: ['00:50:56:a1:3c:09'], links: [], name: 'web-vm-a', deviceType: 'SERVER', vendor: 'VMware', macKind: 'VIRTUAL_MACHINE',
  addresses: [{ ip: '10.0.0.70', firstSnapshot: 1, lastSnapshot: 3 }], seenInFileIds: ['f1', 'f3'], lastFileId: 'f3', lastKey: '10.0.0.70',
  flags: [
    { kind: 'duplicate-mac', severity: 'high', text: 'Duplicate MAC? Possibly more than one machine' },
    { kind: 'vm-mac', severity: 'medium', text: 'VMware virtual machine MAC: VMs cloned from one image often share a MAC.' },
  ],
}

function page(data: unknown[]) {
  return { data, page: 1, pageSize: 20, total: data.length, totalPages: 1 }
}

function renderModal() {
  return render(
    <MemoryRouter>
      <NetworkDevicesModal show networkId="n1" networkName="HQ office" snapshots={snapshots} onHide={() => {}} />
    </MemoryRouter>,
  )
}

describe('NetworkDevicesModal (#918 slice 4)', () => {
  it('lists devices with the addresses they used, where they were seen, and their irregularities', async () => {
    server.use(
      http.get('*/monitor/networks/n1/devices', () => HttpResponse.json(page([laptop, clone]))),
      http.get('*/monitor/networks/n1/device-counts', () => HttpResponse.json({ all: 2, irregular: 1, privateMac: 0 })),
      http.get('*/monitor/networks/n1/device-link-suggestions', () => HttpResponse.json([])),
    )
    renderModal()
    const rows = await screen.findAllByTestId('device-row')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('LAPTOP-ALICE')
    expect(rows[0]).toHaveTextContent('10.0.0.73')
    expect(rows[0]).toHaveTextContent("Alice's laptop")
    expect(within(rows[0]).getByTestId('device-seen')).toHaveAccessibleName('Seen in 3 of 3 snapshots')
    expect(within(rows[1]).getAllByTestId('device-flag')[0]).toHaveTextContent('Duplicate MAC?')
    expect(rows[1]).toHaveTextContent('Virtual machine')
    expect(await screen.findByRole('button', { name: 'Irregular 1' })).toBeInTheDocument()
  })

  it('narrows to irregular devices and searches, asking the server', async () => {
    const seen: string[] = []
    server.use(
      http.get('*/monitor/networks/n1/devices', ({ request }) => {
        const u = new URL(request.url)
        seen.push(`${u.searchParams.get('show') ?? ''}|${u.searchParams.get('q') ?? ''}`)
        return HttpResponse.json(page(u.searchParams.get('show') === 'irregular' ? [clone] : [laptop, clone]))
      }),
      http.get('*/monitor/networks/n1/device-counts', () => HttpResponse.json({ all: 2, irregular: 1, privateMac: 0 })),
      http.get('*/monitor/networks/n1/device-link-suggestions', () => HttpResponse.json([])),
    )
    const user = userEvent.setup()
    renderModal()
    await screen.findAllByTestId('device-row')
    await user.click(screen.getByRole('button', { name: /^Irregular/ }))
    await waitFor(() => expect(screen.getAllByTestId('device-row')).toHaveLength(1))
    await user.type(screen.getByLabelText('Search devices'), 'web')
    await waitFor(() => expect(seen).toContain('irregular|web'))
  })

  it('opens one device: where it was in each snapshot, and a way to its latest snapshot', async () => {
    server.use(
      http.get('*/monitor/networks/n1/devices', () => HttpResponse.json(page([laptop]))),
      http.get('*/monitor/networks/n1/device-counts', () => HttpResponse.json({ all: 1, irregular: 0, privateMac: 0 })),
      http.get('*/monitor/networks/n1/device-link-suggestions', () => HttpResponse.json([])),
    )
    const user = userEvent.setup()
    renderModal()
    await user.click(await screen.findByRole('button', { name: 'LAPTOP-ALICE' }))
    const detail = screen.getByTestId('device-detail')
    expect(within(detail).getAllByRole('img', { name: 'Seen in snapshot 3' })).toHaveLength(1)
    expect(within(detail).getByRole('link', { name: 'Open the latest snapshot it was seen in' })).toHaveAttribute('href', '/analysis/f3')
    await user.click(screen.getByRole('button', { name: 'Devices' }))
    expect(await screen.findAllByTestId('device-row')).toHaveLength(1)
  })

  it('suggests two private MACs as one phone, and links them with a reason (#918 slice 4b)', async () => {
    const bobA = { ...laptop, mac: '3a:1f:9c:52:0e:11', macs: ['3a:1f:9c:52:0e:11'], name: 'Bobs-iPhone', macKind: 'PRIVATE', label: null, addresses: [{ ip: '10.0.0.61', firstSnapshot: 1, lastSnapshot: 1 }], seenInFileIds: ['f1'] }
    const bobB = { ...bobA, mac: '7e:02:41:9a:c3:07', macs: ['7e:02:41:9a:c3:07'], addresses: [{ ip: '10.0.0.88', firstSnapshot: 2, lastSnapshot: 3 }], seenInFileIds: ['f2', 'f3'] }
    const linked = { ...bobB, macs: [bobA.mac, bobB.mac], links: [{ id: 9, macA: bobA.mac, macB: bobB.mac, decision: 'same', reason: 'rotated', actor: 'ana' }] }
    let isLinked = false
    let body: Record<string, unknown> | null = null
    server.use(
      http.get('*/monitor/networks/n1/devices', () => HttpResponse.json(page(isLinked ? [linked] : [bobB, bobA]))),
      http.get('*/monitor/networks/n1/device-counts', () => HttpResponse.json({ all: isLinked ? 1 : 2, irregular: 0, privateMac: isLinked ? 1 : 2 })),
      http.get('*/monitor/networks/n1/device-link-suggestions', () => HttpResponse.json(isLinked ? [] : [{
        macA: bobA.mac, nameA: 'Bobs-iPhone', firstSnapshotA: 1, lastSnapshotA: 1,
        macB: bobB.mac, nameB: 'Bobs-iPhone', firstSnapshotB: 2, lastSnapshotB: 3,
        evidence: [
          { strength: 'strong', what: 'Same DHCP fingerprint', detail: 'Same options in the same order.' },
          { strength: 'medium', what: 'Same hostname', detail: 'Both called themselves "Bobs-iPhone".' },
        ],
      }])),
      http.post('*/monitor/networks/n1/device-links', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        isLinked = true
        return HttpResponse.json(linked.links[0], { status: 201 })
      }),
    )
    const user = userEvent.setup()
    renderModal()
    const suggestion = await screen.findByTestId('device-suggestion')
    expect(suggestion).toHaveTextContent('2 private MACs look like one device: Bobs-iPhone')
    expect(suggestion).toHaveTextContent('Same DHCP fingerprint')
    await user.click(within(suggestion).getByRole('button', { name: 'Same device' }))
    const link = await screen.findByRole('button', { name: 'Link as one device' })
    expect(link).toBeDisabled() // a reason is required
    await user.type(screen.getByLabelText('Reason'), 'rotated its private address')
    await user.click(link)
    expect(body).toEqual({ macA: bobA.mac, macB: bobB.mac, decision: 'same', reason: 'rotated its private address' })
    await waitFor(() => expect(screen.getAllByTestId('device-row')).toHaveLength(1))
    expect(screen.getByTestId('device-row')).toHaveTextContent(bobA.mac)
    expect(screen.queryByTestId('device-suggestion')).not.toBeInTheDocument()
  })
})
