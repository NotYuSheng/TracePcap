import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'

import { MixBar, type MixRow } from '../MixBar'

const row = (name: string, percentage: number): MixRow => ({ name, packets: percentage * 10, bytes: percentage * 100, percentage, color: '#888' })

describe('MixBar', () => {
  it('keeps the busiest rows when it cuts the table, whatever order they came in', () => {
    // Alphabetical, the way the API sends protocols.
    const rows = [row('ARP', 0.4), row('BGP', 0.5), row('DNS', 6.6), row('RTP', 13.1), row('TCP', 17.6), row('UDP', 4.4)]
    render(<MixBar title="Protocols" column="Protocol" rows={rows} limit={3} />)
    const names = within(screen.getByRole('table')).getAllByRole('row').slice(1).map(r => (r as HTMLTableRowElement).cells[0].textContent)
    expect(names).toEqual(['TCP', 'RTP', 'DNS'])
    fireEvent.click(screen.getByRole('button', { name: 'Show all 6' }))
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(7)
  })
})
