/**
 * Per-snapshot role editing (#369). The semantics are the sharp edge: a role set here applies
 * from this snapshot *forward* and leaves earlier ones alone. An analyst who assumes it relabels
 * the whole timeline will silently disagree with what monitor mode reports for older snapshots.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { insightsService } from '@/features/insights/services/insightsService'
import { RoleEditModal } from '../RoleEditModal'

vi.mock('@/features/insights/services/insightsService', () => ({
  insightsService: {
    getNodeRole: vi.fn(),
    suggestNodeRolePreview: vi.fn(),
    upsertNodeRole: vi.fn(),
    dismissNodeRoleStaleness: vi.fn(),
  },
}))

const mocked = vi.mocked(insightsService)
const FILE = '11111111-1111-1111-1111-111111111111'

afterEach(() => vi.resetAllMocks())

function renderModal() {
  const onClose = vi.fn()
  const onSaved = vi.fn()
  render(
    <RoleEditModal
      entityType="IP"
      entityKey="10.0.0.1"
      fileId={FILE}
      snapshotName="monday.pcap"
      onClose={onClose}
      onSaved={onSaved}
    />
  )
  return { onClose, onSaved }
}

describe('RoleEditModal', () => {
  it('states that the edit applies forward and not backward', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)
    renderModal()

    // The one thing a user must not get wrong. Losing this wording turns a scoped edit into an
    // assumed retroactive one.
    expect(screen.getByText(/carries forward/)).toBeInTheDocument()
    expect(screen.getByText(/Earlier snapshots are\s+not changed/)).toBeInTheDocument()
  })

  it('loads the existing role into the form', async () => {
    mocked.getNodeRole.mockResolvedValue({
      roleLabel: 'branch printer',
      roleDescription: 'prints things',
    } as never)

    renderModal()

    await waitFor(() =>
      expect(screen.getByDisplayValue('branch printer')).toBeInTheDocument()
    )
    expect(screen.getByDisplayValue('prints things')).toBeInTheDocument()
  })

  it('starts blank when the entity has no role in this snapshot', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)

    renderModal()

    // A role carried forward from an earlier snapshot must not be pre-filled here as though it
    // were set on this one.
    await waitFor(() => expect(mocked.getNodeRole).toHaveBeenCalled())
    const label = await screen.findByPlaceholderText(/File Server/i)
    expect(label).toHaveValue('')
  })

  it('fills the form from an AI suggestion without saving it', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)
    mocked.suggestNodeRolePreview.mockResolvedValue({
      roleLabel: 'file server',
      roleDescription: 'serves files',
    } as never)
    renderModal()
    await waitFor(() => expect(mocked.getNodeRole).toHaveBeenCalled())

    await userEvent.click(screen.getByRole('button', { name: /suggest/i }))

    // Preview, not persist: the analyst reviews before committing, so nothing is written until
    // they press Save.
    await waitFor(() => expect(screen.getByDisplayValue('file server')).toBeInTheDocument())
    expect(mocked.upsertNodeRole).not.toHaveBeenCalled()
  })

  it('surfaces the reason a suggestion could not be made', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)
    mocked.suggestNodeRolePreview.mockRejectedValue(new Error('Only 2 conversations seen'))
    renderModal()
    await waitFor(() => expect(mocked.getNodeRole).toHaveBeenCalled())

    await userEvent.click(screen.getByRole('button', { name: /suggest/i }))

    // insightsService turns a 422 into this message; swallowing it leaves the analyst pressing
    // a button that appears to do nothing.
    expect(await screen.findByText(/Only 2 conversations seen/)).toBeInTheDocument()
  })

  it('saves as a human-confirmed role scoped to this snapshot', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)
    mocked.upsertNodeRole.mockResolvedValue({} as never)
    const { onSaved, onClose } = renderModal()
    await waitFor(() => expect(mocked.getNodeRole).toHaveBeenCalled())

    await userEvent.type(await screen.findByPlaceholderText(/File Server/i), 'printer')
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }))

    // `true` is the confirmed flag and fileId is the snapshot scope — dropping either turns a
    // deliberate per-snapshot label into an unconfirmed global one.
    await waitFor(() =>
      expect(mocked.upsertNodeRole).toHaveBeenCalledWith('IP', '10.0.0.1', 'printer', '', true, FILE)
    )
    expect(onSaved).toHaveBeenCalled()
    expect(onClose).toHaveBeenCalled()
  })

  it('refuses to save an empty label', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)
    renderModal()
    await waitFor(() => expect(mocked.getNodeRole).toHaveBeenCalled())

    // A blank role is worse than none: it occupies the label slot and carries forward, hiding
    // the fact that the host was never identified.
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^save$/i })).toBeDisabled()
    )
  })

  it('keeps the modal open and reports the failure when a save fails', async () => {
    mocked.getNodeRole.mockResolvedValue(null as never)
    mocked.upsertNodeRole.mockRejectedValue(new Error('offline'))
    const { onClose } = renderModal()
    await waitFor(() => expect(mocked.getNodeRole).toHaveBeenCalled())

    // Save is disabled until the label is non-empty, so a role cannot be saved as blank.
    await userEvent.type(await screen.findByPlaceholderText(/File Server/i), 'printer')
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }))

    // Closing on failure would discard the analyst's typing and imply it was stored.
    expect(await screen.findByText(/Failed to save role/)).toBeInTheDocument()
    expect(onClose).not.toHaveBeenCalled()
  })
})
