import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { DetectionRulesPanel } from '../DetectionRulesPanel'

const rule = {
  id: 'r1',
  scope: 'GLOBAL',
  name: 'c2_beacon',
  description: 'Beacon to C2',
  severity: 'critical',
  enabled: true,
  match: { dstPort: 4444 },
  payloadContains: [],
  payloadRegex: [{ pattern: 'beacon-[0-9]+', caseInsensitive: false }],
  matchAll: false,
  deviceType: null,
  version: 3,
  createdAt: '2026-11-08T10:00:00',
  createdBy: 'alice',
  updatedAt: '2026-11-08T11:00:00',
  updatedBy: 'bob',
}

function me(allowed: boolean) {
  return {
    username: 'system',
    authEnabled: false,
    admin: false,
    canManagePermissions: false,
    permissions: [
      {
        action: 'DETECTION_RULES_GLOBAL',
        label: 'Edit global detection rules',
        description: '',
        level: allowed ? 'ANALYST' : 'ADMIN',
        defaultLevel: 'ANALYST',
        allowed,
        reason: allowed ? null : 'only admins can change this.',
      },
    ],
  }
}

describe('DetectionRulesPanel (#925 phase 1)', () => {
  it('lists rules with what they match and who changed them, and searches', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/detection-rules', () => HttpResponse.json([rule, { ...rule, id: 'r2', name: 'tor_use', match: { app: 'TOR' }, payloadRegex: [] }]))
    )
    render(<DetectionRulesPanel />)

    const row = (await screen.findByText('c2_beacon')).closest('tr')!
    expect(row).toHaveTextContent('dstPort 4444 · payload: 1 regex')
    expect(row).toHaveTextContent('bob')
    expect(row).toHaveTextContent('v3')

    await userEvent.type(screen.getByLabelText('Search detection rules'), 'tor')
    expect(screen.queryByText('c2_beacon')).not.toBeInTheDocument()
    expect(screen.getByText('tor_use')).toBeInTheDocument()
  })

  it('creates a rule in the form, and shows the server field errors beside the field', async () => {
    let posted: Record<string, unknown> | null = null
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/detection-rules', () => HttpResponse.json([])),
      http.post('*/detection-rules', async ({ request }) => {
        posted = (await request.json()) as Record<string, unknown>
        return HttpResponse.json(
          { message: 'The rule isn\'t valid', validationErrors: { 'match.cidr': 'Not a valid CIDR range, such as 10.0.0.0/8.' } },
          { status: 400 }
        )
      })
    )
    render(<DetectionRulesPanel />)
    await userEvent.click(await screen.findByRole('button', { name: /Add rule/ }))

    // Saving an empty rule is stopped locally, with the reasons.
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.getByText('Give the rule a name.')).toBeInTheDocument()
    expect(screen.getByTestId('rule-match-error')).toHaveTextContent('at least one match field')

    await userEvent.type(screen.getByLabelText('Name'), 'bad_range')
    await userEvent.type(screen.getByLabelText('CIDR range'), '10.0.0.0/99')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Not a valid CIDR range, such as 10.0.0.0/8.')).toBeInTheDocument()
    expect(posted).toMatchObject({ name: 'bad_range', severity: 'medium', enabled: true, match: { cidr: '10.0.0.0/99' } })
  })

  it('toggles a rule on and off with a full update', async () => {
    let sent: Record<string, unknown> | null = null
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/detection-rules', () => HttpResponse.json([rule])),
      http.put('*/detection-rules/r1', async ({ request }) => {
        sent = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ ...rule, enabled: false })
      })
    )
    render(<DetectionRulesPanel />)
    await userEvent.click(await screen.findByLabelText('Disable c2_beacon'))
    await waitFor(() => expect(sent).not.toBeNull())
    expect(sent).toMatchObject({ name: 'c2_beacon', enabled: false, match: { dstPort: 4444 } })
  })

  it('is read-only with the reason when the caller may not edit', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(false))),
      http.get('*/detection-rules', () => HttpResponse.json([rule]))
    )
    render(<DetectionRulesPanel />)
    expect(await screen.findByTestId('rules-locked')).toHaveTextContent('only admins can change this')
    expect(screen.getByRole('button', { name: /Add rule/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Import/ })).toBeDisabled()
    expect(screen.getByLabelText('Disable c2_beacon')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete c2_beacon' })).toBeDisabled()

    // Viewing still works, without a Save button.
    await userEvent.click(screen.getByRole('button', { name: 'View c2_beacon' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText('Name')).toBeDisabled()
    expect(within(dialog).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('reports every problem when an import is rejected, and imports nothing', async () => {
    server.use(
      http.get('*/me', () => HttpResponse.json(me(true))),
      http.get('*/detection-rules', () => HttpResponse.json([])),
      http.post('*/detection-rules/import', () =>
        HttpResponse.json(
          {
            message: '1 problem(s) in the file; nothing was imported',
            validationErrors: { 'rules[1] (bad).payloadRegex[0].pattern': 'Not a valid regular expression.' },
          },
          { status: 400 }
        )
      )
    )
    render(<DetectionRulesPanel />)
    await userEvent.click(await screen.findByRole('button', { name: /Import/ }))
    const file = new File(['signatures: []'], 'rules.yml', { type: 'application/yaml' })
    const dialog = await screen.findByRole('dialog')
    await userEvent.upload(within(dialog).getByLabelText('Rules file'), file)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Import' }))

    expect(await screen.findByText(/nothing was imported/)).toBeInTheDocument()
    expect(screen.getByTestId('import-problems')).toHaveTextContent('rules[1] (bad).payloadRegex[0].pattern')
  })
})
