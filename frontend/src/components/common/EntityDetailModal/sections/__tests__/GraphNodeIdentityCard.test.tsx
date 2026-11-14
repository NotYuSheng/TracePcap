/**
 * The node dialog's identity card: the facts that say what a host is, and the one-click confirm
 * while the type is still a machine guess.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { GraphNode } from '@/features/network/types'
import { adjudicationService } from '@/features/insights/services/adjudicationService'
import { GraphNodeIdentityCard } from '../GraphNodeIdentityCard'

vi.mock('@/features/insights/services/adjudicationService', () => ({
  adjudicationService: { setOverride: vi.fn() },
}))

const mocked = vi.mocked(adjudicationService)

function node(extra: Partial<GraphNode['data']> = {}): GraphNode {
  return {
    id: '10.20.10.21',
    label: 'LAPTOP-ANNA',
    type: 'unknown',
    data: {
      ip: '10.20.10.21',
      mac: 'f8:bc:12:a0:00:01',
      hostname: 'LAPTOP-ANNA',
      manufacturer: 'Dell Inc.',
      packetsSent: 111,
      packetsReceived: 7,
      bytesSent: 0,
      bytesReceived: 0,
      totalBytes: 0,
      role: 'client',
      protocols: [],
      connections: 0,
      nodeType: 'unknown',
      nodeTypeEvidence: {},
      identityLabel: 'LAPTOP_DESKTOP',
      identityBasis: 'MACHINE',
      identityContested: true,
      identityCandidates: [
        { label: 'ROUTER', source: 'rules', score: 25 },
        { label: 'LAPTOP_DESKTOP', source: 'rules', score: 45 },
      ],
      ...extra,
    },
  } as GraphNode
}

function renderCard(n: GraphNode, onShowEvidence = vi.fn()) {
  render(
    <GraphNodeIdentityCard
      node={n}
      fileId="f1"
      identityKey="10.20.10.21"
      titleId="t"
      onShowEvidence={onShowEvidence}
      onShowConversations={vi.fn()}
      onClose={vi.fn()}
    />,
  )
}

afterEach(() => vi.resetAllMocks())

describe('GraphNodeIdentityCard', () => {
  it('names the host and lists its identifying facts', () => {
    renderCard(node())
    expect(screen.getByRole('heading', { name: 'LAPTOP-ANNA' })).toBeInTheDocument()
    expect(screen.getByText('f8:bc:12:a0:00:01')).toBeInTheDocument()
    expect(screen.getByText('Dell Inc.')).toBeInTheDocument()
    expect(screen.getByText('the signals disagree')).toBeInTheDocument()
  })

  it('confirms a candidate as a human override, best candidate first', async () => {
    mocked.setOverride.mockResolvedValue(undefined as never)
    renderCard(node())
    const box = screen.getByTestId('node-confirm')
    const buttons = Array.from(box.querySelectorAll('button')).map(b => b.textContent)
    expect(buttons).toEqual(['Laptop / Desktop', 'Router', 'Other…'])
    fireEvent.click(screen.getByRole('button', { name: 'Router' }))
    await waitFor(() => expect(screen.getByText('confirmed')).toBeInTheDocument())
    expect(mocked.setOverride).toHaveBeenCalledWith(
      'f1',
      'host-identity',
      '10.20.10.21',
      'ROUTER',
      'Confirmed from the node dialog',
    )
    expect(screen.queryByTestId('node-confirm')).not.toBeInTheDocument()
  })

  it('sends Other… to the evidence tab', () => {
    const onShowEvidence = vi.fn()
    renderCard(node(), onShowEvidence)
    fireEvent.click(screen.getByRole('button', { name: 'Other…' }))
    expect(onShowEvidence).toHaveBeenCalled()
  })

  it('asks nothing once a person has confirmed the type', () => {
    renderCard(node({ identityBasis: 'HUMAN', identityContested: false }))
    expect(screen.queryByTestId('node-confirm')).not.toBeInTheDocument()
    expect(screen.getByText('confirmed')).toBeInTheDocument()
  })
})
