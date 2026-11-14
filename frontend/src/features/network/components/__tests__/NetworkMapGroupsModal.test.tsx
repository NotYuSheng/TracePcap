import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { GraphNode } from '../../types'
import { buildGroupTree } from '../../services/networkGroups'
import { NetworkMapGroupsModal } from '../NetworkMapGroupsModal'
import { EMPTY_MAP_EDITS, groupingEdits, type NetworkMapEdits } from '../../services/networkMapEdits'

const node = (id: string) => ({ id, label: id, data: { ip: id, deviceType: 'LAPTOP_DESKTOP' } }) as unknown as GraphNode
const nodes = [node('10.0.0.5')]

function setup(edits: NetworkMapEdits = EMPTY_MAP_EDITS, canEdit = true, focus?: string) {
  const onChange = vi.fn()
  render(
    <NetworkMapGroupsModal tops={buildGroupTree(nodes, groupingEdits(edits))} edits={edits} focus={focus} canEdit={canEdit}
      cannotEditReason="Needs Edit network maps." onChange={onChange} onHide={() => {}} />,
  )
  return onChange
}

describe('NetworkMapGroupsModal', () => {
  it('adds a group of your own inside the chosen group', async () => {
    const user = userEvent.setup()
    const onChange = setup()
    await user.type(screen.getByLabelText('New group'), 'Payments')
    await user.click(screen.getByRole('button', { name: 'Add group' }))
    const next: NetworkMapEdits = onChange.mock.calls[0][0]
    expect(next.groups).toHaveLength(1)
    expect(next.groups[0]).toMatchObject({ name: 'Payments', parentId: 'network:other' })
    expect(next.groups[0].id).toMatch(/^user:[A-Za-z0-9-]+$/)
  })

  it('renames a group and gives it a note; clearing the name goes back to the automatic one', async () => {
    const user = userEvent.setup()
    const onChange = setup()
    await user.click(screen.getByRole('button', { name: 'Edit Your networks' }))
    const name = screen.getByLabelText('Name')
    await user.clear(name)
    await user.type(name, 'Head office')
    await user.type(screen.getByLabelText('Note'), 'Floor 3')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(onChange.mock.calls[0][0]).toMatchObject({ names: { local: 'Head office' }, notes: { local: 'Floor 3' } })
  })

  it('deleting your group drops the devices moved into it', async () => {
    const user = userEvent.setup()
    const edits = { ...EMPTY_MAP_EDITS, groups: [{ id: 'user:a', name: 'Payments', parentId: 'network:other' }], placements: { '10.0.0.5': 'user:a' } }
    const onChange = setup(edits)
    await user.click(screen.getByRole('button', { name: 'Delete Payments' }))
    expect(onChange.mock.calls[0][0]).toMatchObject({ groups: [], placements: {} })
  })

  it('opens on the clicked group; without the permission, says why and edits nothing', () => {
    setup(EMPTY_MAP_EDITS, false, 'local')
    expect(screen.getByText('Needs Edit network maps.')).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toBeDisabled()
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: 'Add group' })).toBeDisabled()
  })
})
