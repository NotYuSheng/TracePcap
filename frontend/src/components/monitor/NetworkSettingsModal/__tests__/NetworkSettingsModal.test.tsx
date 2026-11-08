import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { NetworkSettingsModal } from '../NetworkSettingsModal'

describe('NetworkSettingsModal', () => {
  it('starts from the defaults and says they match how the panels always behaved', () => {
    render(<NetworkSettingsModal show onHide={() => {}} onSave={vi.fn()} />)

    expect(screen.getByLabelText('Count by')).toHaveValue('SNAPSHOTS')
    expect(screen.getByLabelText('Number of captures')).toHaveValue(1)
    expect(screen.getByTestId('rule-preview')).toHaveTextContent('as soon as it is missing from the latest capture')
    expect(screen.getByTestId('rule-preview')).toHaveTextContent('This is the default')
  })

  it('saves a days rule', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const onHide = vi.fn()
    render(<NetworkSettingsModal show onHide={onHide} onSave={onSave} />)

    await userEvent.selectOptions(screen.getByLabelText('Count by'), 'DAYS')
    const days = screen.getByLabelText('Number of days')
    await userEvent.clear(days)
    await userEvent.type(days, '14')
    expect(screen.getByTestId('rule-preview')).toHaveTextContent('more than 14 days before the latest capture')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))

    expect(onSave).toHaveBeenCalledWith({ inactivityMode: 'DAYS', inactivityThreshold: 14 })
    expect(onHide).toHaveBeenCalled()
  })

  it('will not save zero or a fraction', async () => {
    render(<NetworkSettingsModal show onHide={() => {}} onSave={vi.fn()} />)
    const n = screen.getByLabelText('Number of captures')

    for (const bad of ['0', '2.5']) {
      await userEvent.clear(n)
      await userEvent.type(n, bad)
      expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    }
  })

  it('shows the network\'s current rule, and can reset it to the default', async () => {
    render(
      <NetworkSettingsModal
        show
        onHide={() => {}}
        initial={{ inactivityMode: 'SNAPSHOTS', inactivityThreshold: 3 }}
        onSave={vi.fn()}
      />
    )
    expect(screen.getByLabelText('Number of captures')).toHaveValue(3)

    await userEvent.click(screen.getByRole('button', { name: 'Reset to default' }))
    expect(screen.getByLabelText('Number of captures')).toHaveValue(1)
  })
})
