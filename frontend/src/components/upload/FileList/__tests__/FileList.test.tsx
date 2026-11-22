/**
 * The captures list against a mocked files API: the page-size menu stays while it can still matter,
 * and a star marks a favourite.
 */
import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { HttpResponse, http } from 'msw'

import { apiUrl, server } from '@/test/msw'
import { FileList } from '../FileList'

const files = Array.from({ length: 60 }, (_, i) => ({
  fileId: `00000000-0000-0000-0000-${String(i).padStart(12, '0')}`,
  fileName: `cap-${i}.pcap`,
  fileSize: 1000,
  uploadedAt: [2026, 11, 15, 10, 0],
  status: 'COMPLETED',
  source: 'ANALYSIS',
  favourite: i === 0,
  uploadedBy: i === 1 ? 'ana' : i === 2 ? 'system' : undefined,
}))

function serve(favourites: string[] = []) {
  server.use(
    // Who's asking (roles, #915): login off, so every capture action is allowed.
    http.get(apiUrl('/me'), () =>
      HttpResponse.json({ username: 'system', authEnabled: false, admin: false, canManagePermissions: false, roles: [], permissions: [] })
    ),
    http.get(apiUrl('/files'), ({ request }) => {
      const u = new URL(request.url)
      const size = Number(u.searchParams.get('pageSize') ?? 20)
      const page = Number(u.searchParams.get('page') ?? 1)
      const list = u.searchParams.get('favourite') === 'true' ? files.filter(f => f.favourite) : files
      return HttpResponse.json({
        data: list.slice((page - 1) * size, page * size),
        page,
        pageSize: size,
        total: list.length,
        totalPages: Math.ceil(list.length / size),
      })
    }),
    http.get(apiUrl('/system/limits'), () => HttpResponse.json({ fileRetentionHours: 12 })),
    http.get(apiUrl('/network-memberships'), () => HttpResponse.json([])),
    http.get(apiUrl('/detection-rules/stale-captures'), () => HttpResponse.json([])),
    http.put(apiUrl('/files/:id/favourite'), ({ params }) => {
      favourites.push(String(params.id))
      return new HttpResponse(null, { status: 204 })
    })
  )
}

const renderList = () =>
  render(
    <MemoryRouter>
      <FileList defaultPageSize={5} />
    </MemoryRouter>
  )

describe('FileList', () => {
  it('keeps the page-size menu after picking a size that fits every capture', async () => {
    serve()
    renderList()
    const menu = await screen.findByLabelText(/items per page/i, { selector: 'select' })
    fireEvent.change(menu, { target: { value: '100' } })
    // All 60 on one page now, and the menu is still there to pick a smaller size.
    // By text, not role: a role query computes the accessibility tree of all 60 rows on every
    // retry, which ran past the 5 s test timeout on a busy CI runner (#956).
    await waitFor(() => expect(screen.getAllByText(/^cap-\d+\.pcap$/, { selector: 'a' })).toHaveLength(60))
    expect(screen.getByLabelText(/items per page/i, { selector: 'select' })).toBeInTheDocument()
    // 60 rows: give a busy CI runner room (it once took 5.1 s against the 5 s default).
  }, 15_000)

  it('stars a capture as a favourite', async () => {
    const favourites: string[] = []
    serve(favourites)
    renderList()
    const star = await screen.findByRole('button', { name: 'Favourite cap-1.pcap' })
    expect(star).toHaveAttribute('aria-pressed', 'false')
    fireEvent.click(star)
    await waitFor(() => expect(favourites).toEqual([files[1].fileId]))
    expect(screen.getByRole('button', { name: 'Unfavourite cap-1.pcap' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('says who uploaded a capture, and has no separate Open button (the name opens it)', async () => {
    serve()
    renderList()
    await screen.findByRole('link', { name: 'cap-1.pcap' })
    // Every row says who uploaded it, or that it wasn't recorded: a blank looked like a missing feature.
    const uploaders = screen.getAllByTestId('capture-uploader').map(u => u.textContent?.trim())
    expect(uploaders).toContain('· by ana')
    expect(uploaders.every(u => /by ana|uploader not recorded|uploaded without sign-in/.test(u ?? ''))).toBe(true)
    // The row's own action button is gone; Open stays in the row's ⋯ menu.
    expect(document.querySelector('.captures-open')).toBeNull()
  })
})
