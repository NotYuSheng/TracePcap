/**
 * The conversation filter state lives entirely in the URL, so this hook is the only thing
 * standing between a shared link and the table it is meant to reproduce. None of it was
 * tested: 14 hooks, zero tests.
 *
 * These cover the behaviour that is easy to break and invisible when broken — page reset,
 * default omission, and the sort pairing — rather than re-asserting every field.
 */
import { renderHook, act } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { useConversationFilters } from '../useConversationFilters'

/** Renders the hook under a router seeded with `search`, exposing the resulting URL too. */
function renderFilters(search = '') {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={[`/conversations${search}`]}>{children}</MemoryRouter>
  )
  return renderHook(
    () => ({ ...useConversationFilters(), location: useLocation() }),
    { wrapper }
  )
}

describe('useConversationFilters', () => {
  it('parses comma-separated lists and scalars out of the query string', () => {
    const { result } = renderFilters('?ip=10.0.0.1&protocols=TCP,UDP&hasRisks=true')

    expect(result.current.filters.ip).toBe('10.0.0.1')
    expect(result.current.filters.protocols).toEqual(['TCP', 'UDP'])
    expect(result.current.filters.hasRisks).toBe(true)
  })

  it('trims blanks out of a list rather than yielding empty entries', () => {
    // "TCP,,UDP , " is what a half-edited URL looks like; an empty protocol would be sent
    // to the backend as a filter that matches nothing.
    const { result } = renderFilters('?protocols=TCP,,UDP%20,%20')

    expect(result.current.filters.protocols).toEqual(['TCP', 'UDP'])
  })

  it('defaults page to 1 and rejects a page below it', () => {
    const { result } = renderFilters('?page=0')

    expect(result.current.filters.page).toBe(1)
  })

  it('counts only real filters, not sorting or pagination', () => {
    const { result } = renderFilters('?ip=10.0.0.1&protocols=TCP&sortBy=startTime&page=3')

    // Sorting and paging are not filters: counting them would light up the "filters active"
    // badge for a user who has only changed page.
    expect(result.current.activeFilterCount).toBe(2)
  })

  it('resets to page 1 when a filter changes', () => {
    const { result } = renderFilters('?page=4')

    act(() => result.current.setFilters({ ip: '10.0.0.9' }))

    // Staying on page 4 of a newly narrowed result set usually shows an empty table.
    expect(result.current.filters.page).toBe(1)
    expect(result.current.location.search).not.toContain('page=')
  })

  it('keeps an explicitly requested page', () => {
    const { result } = renderFilters('?ip=10.0.0.1')

    act(() => result.current.setFilters({ page: 3 }))

    expect(result.current.filters.page).toBe(3)
  })

  it('omits defaults from the URL so shared links stay short', () => {
    const { result } = renderFilters()

    act(() => result.current.setFilters({ ip: '10.0.0.1' }))

    expect(result.current.location.search).toContain('ip=10.0.0.1')
    expect(result.current.location.search).not.toContain('pageSize=')
    expect(result.current.location.search).not.toContain('hasRisks=')
  })

  it('drops sortDir when no sort field is set', () => {
    const { result } = renderFilters()

    act(() => result.current.setFilters({ sortDir: 'desc' }))

    // sortDir alone means nothing to the backend, and leaving it in the URL implies a sort
    // the table is not applying.
    expect(result.current.location.search).not.toContain('sortDir=')
  })

  it('writes sortDir once a sort field is chosen', () => {
    const { result } = renderFilters()

    act(() => result.current.setFilters({ sortBy: 'startTime', sortDir: 'desc' }))

    expect(result.current.location.search).toContain('sortBy=startTime')
    expect(result.current.location.search).toContain('sortDir=desc')
  })

  it('merges into existing filters rather than replacing them', () => {
    const { result } = renderFilters('?ip=10.0.0.1&protocols=TCP')

    act(() => result.current.setFilters({ port: '443' }))

    expect(result.current.filters.ip).toBe('10.0.0.1')
    expect(result.current.filters.protocols).toEqual(['TCP'])
    expect(result.current.filters.port).toBe('443')
  })

  it('clearAll empties the query string', () => {
    const { result } = renderFilters('?ip=10.0.0.1&protocols=TCP&page=2')

    act(() => result.current.clearAll())

    expect(result.current.location.search).toBe('')
    expect(result.current.activeFilterCount).toBe(0)
  })
})
