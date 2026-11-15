import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it, vi } from 'vitest'
import { server } from '@/test/msw'
// The diagram pulls in a WebGL renderer, which jsdom doesn't have.
vi.mock('@components/monitor/SubnetDiagramModal/SubnetDiagramModal', () => ({ SubnetDiagramModal: () => null }))
import { SubnetsPanel } from '../SubnetsPanel'
import type { SubnetDefinition } from '@/features/subnets/types/subnet.types'

const base = { description: null, source: 'MANUAL' as const, confirmed: true }
const subnets: SubnetDefinition[] = [
  { ...base, id: 1, cidr: '10.0.0.0/24', label: 'Office', scope: 'default' },
  { ...base, id: 2, cidr: '10.0.1.0/24', label: 'HQ servers', scope: 'network', overridesDefault: true },
]

describe('SubnetsPanel in a network (#915 phase 4b)', () => {
  it("hides a default subnet in this network, and reverts the network's own", async () => {
    const posts: unknown[] = []
    const deletes: string[] = []
    server.use(
      http.post('*/monitor/networks/n1/subnets', async ({ request }) => {
        posts.push(await request.json())
        return HttpResponse.json({}, { status: 201 })
      }),
      http.delete('*/monitor/networks/n1/subnets/:id', ({ params }) => {
        deletes.push(String(params.id))
        return new HttpResponse(null, { status: 204 })
      })
    )
    const onChanged = vi.fn()
    const user = userEvent.setup()
    render(<SubnetsPanel networkId="n1" subnets={subnets} snapshots={[]} onSaved={() => {}} onDeleted={() => {}} onChanged={onChanged} />)
    expect(screen.getByText('overridden here')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Hide 10.0.0.0/24 in this network' }))
    await waitFor(() => expect(posts).toContainEqual(expect.objectContaining({ cidr: '10.0.0.0/24', hidden: true })))

    await user.click(screen.getByRole('button', { name: 'Revert 10.0.1.0/24 to the default' }))
    await waitFor(() => expect(deletes).toEqual(['2']))
    expect(onChanged).toHaveBeenCalledTimes(2)
  })

  it('adds a subnet to this network only', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/monitor/networks/n1/subnets', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 9, cidr: '10.5.0.0/24', label: 'Lab', scope: 'network' }, { status: 201 })
      })
    )
    const user = userEvent.setup()
    render(<SubnetsPanel networkId="n1" subnets={[]} snapshots={[]} onSaved={() => {}} onDeleted={() => {}} />)
    await user.click(screen.getByRole('button', { name: /Add Manually/ }))
    expect(screen.getByText(/Adds to this network only/)).toBeInTheDocument()
    await user.type(screen.getByPlaceholderText('e.g. 10.0.0.0/16'), '10.5.0.0/24')
    await user.type(screen.getByPlaceholderText('e.g. Corporate LAN'), 'Lab')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(body).toMatchObject({ cidr: '10.5.0.0/24', label: 'Lab', confirmed: true, networkId: 'n1' }))
  })
})
