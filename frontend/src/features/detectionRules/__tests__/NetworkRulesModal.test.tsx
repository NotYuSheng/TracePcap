import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { NetworkRulesModal } from '../NetworkRulesModal'

const netRule = {
  id: 'n1', scope: 'NETWORK', networkId: 'net-1', name: 'hq_dns', description: null, severity: 'low',
  enabled: true, match: { ip: '10.0.0.53' }, payloadContains: [], payloadRegex: [], matchAll: false,
  version: 2, createdAt: '', createdBy: 'alice', updatedAt: '', updatedBy: 'bob',
}

function me(allowed: boolean) {
  const p = (action: string) => ({
    action, label: action, description: '', level: allowed ? 'ANALYST' : 'ADMIN', defaultLevel: 'ANALYST',
    allowed, reason: allowed ? null : 'only admins can change this.',
  })
  return {
    username: 'system', authEnabled: false, admin: false, canManagePermissions: false,
    permissions: [p('DETECTION_RULES_NETWORK'), p('DETECTION_RULES_GLOBAL')],
  }
}

function serve(allowed: boolean, onPost?: (body: unknown) => void) {
  server.use(
    http.get('*/me', () => HttpResponse.json(me(allowed))),
    http.get('*/monitor/networks/net-1/detection-rules', () => HttpResponse.json([netRule])),
    http.post('*/monitor/networks/net-1/detection-rules', async ({ request }) => {
      onPost?.(await request.json())
      return HttpResponse.json(netRule, { status: 201 })
    }),
    http.get('*/detection-rules/status', () =>
      HttpResponse.json({ captures: 0, staleCaptures: 0, uncheckableCaptures: 0, staleRules: [], uncheckableRules: [] })
    ),
    http.get('*/rule-reapply-jobs', () => HttpResponse.json([]))
  )
}

describe('NetworkRulesModal (#925 phase 3)', () => {
  it("lists the network's rules and adds one to this network", async () => {
    let posted: unknown = null
    serve(true, b => (posted = b))
    render(<NetworkRulesModal show networkId="net-1" networkName="HQ" onHide={() => {}} />)
    expect(await screen.findByText('Detection rules for HQ')).toBeInTheDocument()
    expect(await screen.findByText('hq_dns')).toBeInTheDocument()
    expect(screen.getByText('ip 10.0.0.53')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: /Add rule/ }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('New rule for this network')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'hq_dns_2')
    await userEvent.type(within(dialog).getByLabelText('IP address'), '10.0.0.54')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(posted).toMatchObject({ name: 'hq_dns_2', match: { ip: '10.0.0.54' } }))
  })

  it('is read-only with the reason without the network permission', async () => {
    serve(false)
    render(<NetworkRulesModal show networkId="net-1" networkName="HQ" onHide={() => {}} />)
    expect(await screen.findByText(/You can view these rules but not change them/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Add rule/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete hq_dns' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'View hq_dns' })).toBeEnabled()
  })
})
