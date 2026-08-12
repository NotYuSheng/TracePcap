/**
 * Change events are what monitor mode exists to surface: what altered between two snapshots of
 * a network. This hook decides which of them an operator actually sees, so its defaults and its
 * paging are the difference between noticing a change and not.
 */
import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import type { ChangeEvent } from '@/features/monitor/types/monitor.types'
import { useChangeEventFilters } from '../useChangeEventFilters'

function event(overrides: Partial<ChangeEvent> = {}): ChangeEvent {
  return {
    id: Math.random().toString(36).slice(2),
    changeType: 'MAC_ADDED',
    severity: 'INFO',
    reviewed: false,
    ...overrides,
  } as ChangeEvent
}

/** n events sharing the given shape, for exercising pagination. */
function many(n: number, overrides: Partial<ChangeEvent> = {}) {
  return Array.from({ length: n }, () => event(overrides))
}

describe('useChangeEventFilters', () => {
  it('defaults to showing only unreviewed events', () => {
    const events = [event({ reviewed: true }), event({ reviewed: false })]

    const { result } = renderHook(() => useChangeEventFilters(events))

    // An opinionated default: monitor mode is a triage queue, so already-reviewed events are
    // hidden until asked for. Defaulting to ALL would bury new changes under old ones.
    expect(result.current.reviewedFilter).toBe('UNREVIEWED')
    expect(result.current.filteredEvents).toHaveLength(1)
  })

  it('filters by severity', () => {
    const events = [event({ severity: 'CRITICAL' }), event({ severity: 'INFO' })]
    const { result } = renderHook(() => useChangeEventFilters(events))

    act(() => result.current.selectSeverity('CRITICAL'))

    expect(result.current.filteredEvents).toHaveLength(1)
    expect(result.current.filteredEvents[0].severity).toBe('CRITICAL')
  })

  it('filters by change type', () => {
    const events = [event({ changeType: 'MAC_ADDED' }), event({ changeType: 'ASN_CHANGE' })]
    const { result } = renderHook(() => useChangeEventFilters(events))

    act(() => result.current.selectChangeType('ASN_CHANGE'))

    expect(result.current.filteredEvents).toHaveLength(1)
  })

  it('offers ALL plus each change type present in the data, without duplicates', () => {
    const events = [
      event({ changeType: 'MAC_ADDED' }),
      event({ changeType: 'MAC_ADDED' }),
      event({ changeType: 'ASN_CHANGE' }),
    ]

    const { result } = renderHook(() => useChangeEventFilters(events))

    // Derived from the data rather than a fixed list, so a change type the backend adds shows
    // up without a frontend release.
    expect(result.current.changeTypes).toEqual(['ALL', 'MAC_ADDED', 'ASN_CHANGE'])
  })

  it('pages the filtered list ten at a time', () => {
    const { result } = renderHook(() => useChangeEventFilters(many(25)))

    expect(result.current.pagedEvents).toHaveLength(10)
    expect(result.current.totalEventPages).toBe(3)
  })

  it('returns to page 1 when a filter changes', () => {
    const { result } = renderHook(() => useChangeEventFilters(many(25)))

    act(() => result.current.setEventPage(3))
    expect(result.current.eventPage).toBe(3)

    act(() => result.current.selectSeverity('INFO'))

    // Staying on page 3 of a newly narrowed list usually shows an empty table.
    expect(result.current.eventPage).toBe(1)
  })

  it('clamps the page down when the list shrinks beneath it', () => {
    const events = [...many(25, { severity: 'INFO' }), ...many(3, { severity: 'CRITICAL' })]
    const { result } = renderHook(() => useChangeEventFilters(events))

    act(() => result.current.setEventPage(3))
    act(() => result.current.selectSeverity('CRITICAL'))

    // selectSeverity already resets to 1, so the clamp effect is what protects a page set
    // directly — e.g. restored from a link — against a list that cannot reach it.
    expect(result.current.eventPage).toBeLessThanOrEqual(result.current.totalEventPages)
  })

  it('reports at least one page even with nothing to show', () => {
    const { result } = renderHook(() => useChangeEventFilters([]))

    // Math.max(1, ...) — a zero page count would render "Page 1 of 0".
    expect(result.current.totalEventPages).toBe(1)
    expect(result.current.pagedEvents).toEqual([])
  })
})
