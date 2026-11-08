import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { AddressDefaultsPanel } from '../AddressDefaultsPanel'

describe('AddressDefaultsPanel (#915 phase 4c)', () => {
  it('edits and deletes the shared default, with no network badges', async () => {
    const posts: unknown[] = []
    const deletes: string[] = []
    server.use(
      http.get('*/me', () => HttpResponse.json({ username: 'system', authEnabled: false, admin: false, canManagePermissions: false, permissions: [] })),
      http.get('*/custom-private-ranges', () => HttpResponse.json([{ id: 5, cidr: '100.64.0.0/10', classification: 'PRIVATE' }])),
      http.get('*/subnets', () => HttpResponse.json([])),
      http.post('*/custom-private-ranges', async ({ request }) => {
        posts.push(await request.json())
        return HttpResponse.json({ id: 5, cidr: '100.64.0.0/10', classification: 'PUBLIC' }, { status: 201 })
      }),
      http.delete('*/custom-private-ranges/:id', ({ params }) => {
        deletes.push(String(params.id))
        return new HttpResponse(null, { status: 204 })
      })
    )
    const user = userEvent.setup()
    render(<AddressDefaultsPanel />)
    await user.click(screen.getByRole('tab', { name: 'Internal / external ranges' }))
    const row = (await screen.findAllByTestId('address-row'))[0]
    expect(row).toHaveTextContent('Internal')
    expect(screen.queryByRole('columnheader', { name: 'From' })).not.toBeInTheDocument()
    expect(within(row).queryByRole('button', { name: 'Hide here' })).not.toBeInTheDocument()

    await user.click(within(row).getByRole('button', { name: 'Edit' }))
    await user.click(await screen.findByLabelText('External'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(posts).toEqual([{ cidr: '100.64.0.0/10', classification: 'PUBLIC' }]))

    await user.click(within(row).getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(deletes).toEqual(['5']))
  })
})
