import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { server } from '@/test/msw'
import { CaptureRulesCard } from '../CaptureRulesCard'
import { RuleScopeTag } from '../RuleScopeTag'

const capRule = {
  id: 'c1',
  scope: 'CAPTURE',
  fileId: 'f1',
  name: 'odd_port',
  description: null,
  severity: 'medium',
  enabled: true,
  match: { dstPort: 5999 },
  payloadContains: [],
  payloadRegex: [],
  matchAll: false,
  version: 1,
  createdAt: '2026-11-08T10:00:00',
  createdBy: 'system',
  updatedAt: '2026-11-08T10:00:00',
  updatedBy: 'system',
}

function me(capture: boolean, global: boolean) {
  const p = (action: string, allowed: boolean) => ({
    action, label: action, description: '', level: allowed ? 'ANALYST' : 'ADMIN', defaultLevel: 'ANALYST',
    allowed, reason: allowed ? null : 'only admins can change this.',
  })
  return {
    username: 'system', authEnabled: false, admin: false, canManagePermissions: false,
    permissions: [p('DETECTION_RULES_CAPTURE', capture), p('DETECTION_RULES_GLOBAL', global)],
  }
}

describe('CaptureRulesCard (#925 phase 3)', () => {
  it('adds a rule to this capture, not a global one', async () => {
    let posted: unknown = null
    const onChanged = vi.fn()
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true, true))),
      http.get('*/files/f1/detection-rules', () => HttpResponse.json(posted ? [capRule] : [])),
      http.post('*/files/f1/detection-rules', async ({ request }) => {
        posted = await request.json()
        return HttpResponse.json(capRule, { status: 201 })
      })
    )
    render(<MemoryRouter><CaptureRulesCard fileId="f1" onChanged={onChanged} /></MemoryRouter>)
    await userEvent.click(await screen.findByRole('button', { name: /Add rule/ }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('New rule for this capture')
    await userEvent.type(within(dialog).getByLabelText('Name'), 'odd_port')
    await userEvent.type(within(dialog).getByLabelText('Destination port'), '5999')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(posted).toMatchObject({ name: 'odd_port', match: { dstPort: 5999 } }))
    expect(await screen.findByText('Rule added and checked against this capture.')).toBeInTheDocument()
    expect(onChanged).toHaveBeenCalled()
    expect(await screen.findByText('odd_port')).toBeInTheDocument()
  })

  it('promotes a rule to global, optionally removing the original', async () => {
    let promoted: unknown = null
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true, true))),
      http.get('*/files/f1/detection-rules', () => HttpResponse.json([capRule])),
      http.post('*/detection-rules/c1/promotions', async ({ request }) => {
        promoted = await request.json()
        return HttpResponse.json({ ...capRule, id: 'g1', scope: 'GLOBAL', promotedFrom: 'c1' }, { status: 201 })
      })
    )
    render(<MemoryRouter><CaptureRulesCard fileId="f1" /></MemoryRouter>)
    await userEvent.click(await screen.findByRole('button', { name: 'Promote odd_port to a global rule' }))
    const dialog = await screen.findByRole('dialog')
    await userEvent.click(within(dialog).getByLabelText("Keep this capture's rule as well"))
    await userEvent.click(within(dialog).getByRole('button', { name: 'Promote' }))
    await waitFor(() => expect(promoted).toEqual({ keepOriginal: false }))
    expect(await screen.findByText(/is now a global rule/)).toBeInTheDocument()
  })

  it('without permission: no adding, editing becomes viewing, promote needs the global permission', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(false, false))),
      http.get('*/files/f1/detection-rules', () => HttpResponse.json([capRule]))
    )
    render(<MemoryRouter><CaptureRulesCard fileId="f1" /></MemoryRouter>)
    expect(await screen.findByText(/You can't add rules here/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Add rule/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete odd_port' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Promote odd_port to a global rule' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'View odd_port' })).toBeEnabled()
  })
})

describe('RuleScopeTag', () => {
  it('labels a match with its scope', () => {
    const { rerender, container } = render(<RuleScopeTag scope="CAPTURE" />)
    expect(container).toHaveTextContent('· capture')
    rerender(<RuleScopeTag scope="GLOBAL" />)
    expect(container).toHaveTextContent('· global')
    rerender(<RuleScopeTag />)
    expect(container).toHaveTextContent('')
  })
})
