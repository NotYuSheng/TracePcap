import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { NetworkAddressConfigModal } from '../NetworkAddressConfigModal'

const subnets = [
  { id: 1, cidr: '10.0.0.0/24', label: 'Office', scope: 'default', hidden: false, overridesDefault: false },
  { id: 2, cidr: '10.0.1.0/24', label: 'HQ servers', scope: 'network', hidden: false, overridesDefault: true },
  { id: 3, cidr: '10.0.2.0/24', label: 'Lab', scope: 'network', hidden: true, overridesDefault: true },
  { id: 4, cidr: '10.9.0.0/16', label: 'Site only', scope: 'network', hidden: false, overridesDefault: false },
]

function me(allowed: boolean) {
  return {
    username: 'system', authEnabled: false, admin: false, canManagePermissions: false,
    permissions: [{ action: 'NETWORK_SETTINGS', label: '', description: '', level: 'ANALYST', defaultLevel: 'ANALYST', allowed, reason: allowed ? null : 'Only admins can edit network settings.' }],
  }
}

function serve(allowed = true) {
  const posts: unknown[] = []
  const deletes: string[] = []
  server.use(
    http.get('*/me', () => HttpResponse.json(me(allowed))),
    http.get('*/monitor/networks/n1/subnets', () => HttpResponse.json(subnets)),
    http.get('*/monitor/networks/n1/ip-org-rules', () =>
      HttpResponse.json([{ id: 9, cidr: '10.0.0.0/8', label: 'Corp', scope: 'default', hidden: false, overridesDefault: false }])),
    http.post('*/monitor/networks/n1/:kind', async ({ request, params }) => {
      posts.push({ kind: params.kind, body: await request.json() })
      return HttpResponse.json({}, { status: 201 })
    }),
    http.delete('*/monitor/networks/n1/:kind/:id', ({ params }) => {
      deletes.push(`${params.kind}/${params.id}`)
      return new HttpResponse(null, { status: 204 })
    })
  )
  return { posts, deletes }
}

function renderModal() {
  return render(<NetworkAddressConfigModal show networkId="n1" networkName="HQ" onHide={() => {}} />)
}

describe('NetworkAddressConfigModal (#915 phase 4)', () => {
  it('shows each entry with where it comes from', async () => {
    serve()
    renderModal()
    const rows = await screen.findAllByTestId('address-row')
    expect(rows).toHaveLength(4)
    expect(rows[0]).toHaveTextContent('default')
    expect(rows[1]).toHaveTextContent('overridden here')
    expect(rows[2]).toHaveTextContent('hidden here')
    expect(rows[3]).toHaveTextContent('this network')
    expect(within(rows[1]).getByRole('button', { name: 'Revert to default' })).toBeInTheDocument()
    expect(within(rows[2]).getByRole('button', { name: 'Show again' })).toBeInTheDocument()
    expect(within(rows[3]).getByRole('button', { name: 'Remove' })).toBeInTheDocument()
  })

  it("overrides a default entry here, hides one, and reverts the network's own", async () => {
    const { posts, deletes } = serve()
    const user = userEvent.setup()
    renderModal()
    const rows = await screen.findAllByTestId('address-row')

    await user.click(within(rows[0]).getByRole('button', { name: 'Override' }))
    const label = await screen.findByLabelText('Label')
    expect(screen.getByLabelText('CIDR or address')).toBeDisabled()
    await user.clear(label)
    await user.type(label, 'HQ office')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(posts).toContainEqual({
        kind: 'subnets',
        body: { cidr: '10.0.0.0/24', label: 'HQ office', confirmed: true, networkId: 'n1' },
      })
    )

    await user.click(within(rows[0]).getByRole('button', { name: 'Hide here' }))
    await waitFor(() =>
      expect(posts).toContainEqual({ kind: 'subnets', body: { cidr: '10.0.0.0/24', hidden: true, confirmed: false, networkId: 'n1' } })
    )

    await user.click(within(rows[1]).getByRole('button', { name: 'Revert to default' }))
    await waitFor(() => expect(deletes).toContain('subnets/2'))
  })

  it('searches, and switches lists', async () => {
    serve()
    const user = userEvent.setup()
    renderModal()
    await screen.findAllByTestId('address-row')
    await user.type(screen.getByRole('searchbox', { name: /Search Subnet labels/ }), 'lab')
    expect(screen.getAllByTestId('address-row')).toHaveLength(1)

    await user.click(screen.getByRole('tab', { name: 'Organisations' }))
    const org = await screen.findByTestId('address-list-ip-org-rules')
    expect(within(org).getByText('Corp')).toBeInTheDocument()
  })

  it("greys out changes the caller can't make, and says why", async () => {
    serve(false)
    renderModal()
    expect(await screen.findByText('Only admins can edit network settings.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Add for this network/ })).toBeDisabled()
    expect(within(screen.getAllByTestId('address-row')[0]).getByRole('button', { name: 'Override' })).toBeDisabled()
  })
})
