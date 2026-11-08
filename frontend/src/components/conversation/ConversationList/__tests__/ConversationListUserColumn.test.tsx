/**
 * The User column (#812): who was logged in on each endpoint when the conversation started. One
 * account is named; several are flagged, not picked; none shows nothing.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { Conversation } from '@/types'
import { ConversationList } from '../ConversationList'

// jsdom has no ResizeObserver; the table's scroll container uses one.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

function conv(overrides: Partial<Conversation>): Conversation {
  return {
    id: 'c1',
    endpoints: [
      { ip: '10.0.0.10', port: 50000 },
      { ip: '10.0.0.1', port: 88 },
    ],
    protocol: { layer: 'transport', name: 'UDP' },
    startTime: '2026-11-01T10:42:00',
    endTime: '2026-11-01T10:43:00',
    durationMs: 60000,
    packetCount: 3,
    totalBytes: 300,
    packets: [],
    direction: 'bidirectional',
    ...overrides,
  } as Conversation
}

function renderRows(c: Conversation) {
  return render(
    <ConversationList
      conversations={[c]}
      sortBy={'' as never}
      sortDir="asc"
      onSort={() => {}}
      visibleColumns={new Set(['source', 'destination', 'users'])}
    />
  )
}

describe('ConversationList User column', () => {
  it('names the one account logged in on an endpoint, with its first login', () => {
    renderRows(conv({ srcAccount: { username: 'bob', accountCount: 1, firstLoginAt: '2026-11-01T09:58:00' } }))

    expect(screen.getByRole('columnheader', { name: 'User' })).toBeInTheDocument()
    expect(screen.getByText('bob')).toBeInTheDocument()
    expect(screen.getByText(/first login/)).toBeInTheDocument()
  })

  it('flags several accounts rather than picking one', () => {
    renderRows(conv({ srcAccount: { username: null, accountCount: 2, firstLoginAt: null } }))

    expect(screen.getByText("2 accounts. See the host's timeline.")).toBeInTheDocument()
  })

  it('shows nothing for an endpoint with no login seen by then', () => {
    renderRows(conv({}))

    expect(screen.queryByText(/src:|dst:/)).not.toBeInTheDocument()
  })
})
