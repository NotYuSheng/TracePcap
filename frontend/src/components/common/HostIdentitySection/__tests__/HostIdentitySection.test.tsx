import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { HostIdentitySection } from '../HostIdentitySection'

const base = {
  ip: '10.0.0.70', primaryLabel: 'SERVER', basis: 'MACHINE', confidence: 40, contested: false,
  candidates: [], serviceRoles: [], ndpiApps: [], initiatedConversations: 1, answeredConversations: 0,
  conversationCount: 1, peerCount: 1,
}

function serve(evidence: Record<string, unknown>) {
  server.use(
    http.get('*/files/f1/hosts/:ip/identity', () => HttpResponse.json({ ...base, ...evidence })),
    http.get('*/custom-private-ranges', () => HttpResponse.json([])),
    http.get('*/files/f1/hosts/:ip/occupancies', () =>
      HttpResponse.json({
        ip: '10.0.0.70', overlapping: false, virtualAddress: false, decisions: [], suggestions: [],
        canEdit: true, occupancies: [{ idx: 0, automatic: false, conversations: 1 }],
      })
    )
  )
}

describe('HostIdentitySection identity checks (#918)', () => {
  it('warns that the host may be more than one machine, with every TTL', async () => {
    serve({
      ttls: [64, 128],
      identityWarning: 'Possibly more than one machine: TTLs from different operating-system families.',
    })
    render(<HostIdentitySection fileId="f1" ip="10.0.0.70" />)
    const warning = await screen.findByTestId('host-identity-warning')
    expect(warning).toHaveTextContent('Possibly more than one machine')
    expect(warning).toHaveTextContent('TTLs seen: 64, 128')
  })

  it("says a failover pair's virtual address isn't a machine", async () => {
    serve({ ip: '10.0.0.254', primaryLabel: 'VIRTUAL_ADDRESS', addressKind: 'VIRTUAL_FAILOVER' })
    render(<HostIdentitySection fileId="f1" ip="10.0.0.254" />)
    expect(await screen.findByTestId('host-virtual-address')).toHaveTextContent('shared virtual address')
    expect(screen.queryByTestId('host-identity-warning')).not.toBeInTheDocument()
  })
})
