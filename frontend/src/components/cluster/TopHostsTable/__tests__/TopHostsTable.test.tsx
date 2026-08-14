/**
 * The top-hosts table ranks who talked most in a capture. Two things make it more than a list:
 * the rank numbers must keep counting across pages, and the geo badge must not overstate how
 * trustworthy a location is.
 */
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { HostSummary } from '@/features/cluster/services/clusterApi'
import { TopHostsTable } from '../TopHostsTable'

/**
 * No `as HostSummary` cast: the cast is what let an earlier version of this fixture invent
 * `totalPackets` and `roleLabel` (the real fields are `packetCount` and `role`) and fail at
 * render instead of at compile time.
 */
function host(ip: string, overrides: Partial<HostSummary> = {}): HostSummary {
  return {
    ip,
    hostname: null,
    hostnameSource: null,
    totalBytes: 1000,
    packetCount: 10,
    conversationCount: 1,
    riskCount: 0,
    country: null,
    org: null,
    geoSource: null,
    deviceType: null,
    role: 'unknown',
    ...overrides,
  }
}

const many = (n: number) => Array.from({ length: n }, (_, i) => host(`10.0.0.${i + 1}`))

function renderTable(hosts: HostSummary[], props: Partial<Parameters<typeof TopHostsTable>[0]> = {}) {
  const onSortByChange = vi.fn()
  render(
    <TopHostsTable
      hosts={hosts}
      loading={false}
      sortBy="bytes"
      onSortByChange={onSortByChange}
      {...props}
    />
  )
  return { onSortByChange }
}

/** Rank cells are the first column of each body row. */
function ranks(): string[] {
  const rows = screen.getAllByRole('row').slice(1) // drop the header
  return rows.map(r => within(r).getAllByRole('cell')[0].textContent ?? '')
}

describe('TopHostsTable', () => {
  it('shows one page of hosts at a time', () => {
    renderTable(many(45))

    expect(screen.getAllByRole('row')).toHaveLength(21) // 20 hosts + header
  })

  it('continues the rank numbering onto the next page', async () => {
    renderTable(many(45))
    expect(ranks()[0]).toBe('1')

    await userEvent.click(screen.getByRole('button', { name: '2' }))

    // Restarting at 1 on page two would make the 21st-busiest host look like the busiest —
    // the ranking is the entire point of the table.
    expect(ranks()[0]).toBe('21')
  })

  it('returns to the first page when the sort changes', async () => {
    const { onSortByChange } = renderTable(many(45))
    await userEvent.click(screen.getByRole('button', { name: '2' }))
    expect(ranks()[0]).toBe('21')

    await userEvent.click(screen.getByRole('button', { name: 'Packets' }))

    // A re-sort makes page two meaningless — those are different hosts now.
    expect(onSortByChange).toHaveBeenCalledWith('packets')
    expect(ranks()[0]).toBe('1')
  })

  it('marks the active sort so the ranking is not ambiguous', () => {
    renderTable(many(3), { sortBy: 'risks' })

    // Without this the table shows an order with no indication of what it is ordered by.
    expect(screen.getByRole('button', { name: 'Risks' })).toHaveClass('btn-primary')
    expect(screen.getByRole('button', { name: 'Bytes' })).not.toHaveClass('btn-primary')
  })

  it('disables sorting while a fetch is in flight', () => {
    renderTable(many(3), { loading: true })

    // Queueing a second sort before the first returns races two responses into one table.
    //
    // Only the disabled state is asserted. The shared Spinner *does* forward `role` — it
    // defaults to "status" — but it also sets aria-hidden="true", which removes it from the
    // accessibility tree, so getByRole('status') cannot reach it. That contradiction is pinned
    // in Spinner's own tests; asserting it from here would test markup this component does not
    // control.
    expect(screen.getByRole('button', { name: 'Packets' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Bytes' })).toBeDisabled()
  })

  describe('geo source badge', () => {
    it('labels a live lookup as Live', () => {
      renderTable([host('8.8.8.8', { country: 'US', geoSource: 'ipinfo' })])

      expect(screen.getByText(/Live/)).toBeInTheDocument()
    })

    it('labels an offline lookup as MMDB', () => {
      renderTable([host('8.8.8.8', { country: 'US', geoSource: 'mmdb' })])

      // The offline database is approximate — cloud IPs frequently resolve to the wrong city.
      // Saying so is what stops an analyst treating it as ground truth.
      expect(screen.getByText(/MMDB/)).toBeInTheDocument()
    })

    it('falls back to the cautious label for an unknown source', () => {
      renderTable([host('8.8.8.8', { country: 'US', geoSource: 'something-new' })])

      // Defaulting to "Live" would overstate the accuracy of a lookup whose provenance is
      // unknown. Understating it is the safe direction.
      expect(screen.getByText(/MMDB/)).toBeInTheDocument()
      expect(screen.queryByText(/Live/)).not.toBeInTheDocument()
    })

    it('shows no badge when no geo lookup happened', () => {
      renderTable([host('10.0.0.1')])

      expect(screen.queryByText(/MMDB|Live/)).not.toBeInTheDocument()
    })
  })
})
