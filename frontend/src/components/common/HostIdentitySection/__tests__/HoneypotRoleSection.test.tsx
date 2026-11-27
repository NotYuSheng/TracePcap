import { render, screen, waitFor } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '@/test/msw'
import { HoneypotRoleSection } from '../HoneypotRoleSection'

const host = {
  host: '10.0.2.15', label: null, honeypot: null, described: null, basis: 'MACHINE', confidence: 0,
  contested: false, candidates: [], signals: [], reason: "nothing it sent matches a honeypot signature, and it doesn't behave like a decoy",
  overriddenBy: null,
}

function serve(over: Record<string, unknown>) {
  server.use(
    http.get('*/files/f1/honeypots/:ip', () =>
      HttpResponse.json({
        hosts: [{ ...host, ...over }], singleSignal: 0, serversChecked: 1, signaturesVersion: '1',
        question: 'honeypot', options: ['Honeypot', 'Not a honeypot'],
      })
    ),
    http.get('*/files/f1/adjudications/honeypot/:ip/override', () => new HttpResponse(null, { status: 404 })),
    http.get('*/files/f1/adjudications/honeypot/:ip/evidence', () => HttpResponse.json([]))
  )
}

describe('HoneypotRoleSection (#1331)', () => {
  it('answers for a host with no signal, so an analyst can still mark it', async () => {
    serve({})
    render(<HoneypotRoleSection fileId="f1" ip="10.0.2.15" />)
    expect(await screen.findByTestId('honeypot-undetermined')).toHaveTextContent('nothing it sent matches')
    const section = screen.getByTestId('host-honeypot-role')
    expect(section).toHaveTextContent('Not settled')
    expect(section).toHaveTextContent('None: nothing it sent or did points at a honeypot.')
  })

  it("shows an analyst's answer, Not a honeypot too, so it can be undone", async () => {
    serve({ label: 'Not a honeypot', basis: 'HUMAN', confidence: 100, described: '10.0.2.15 is not a honeypot', overriddenBy: 'ana' })
    render(<HoneypotRoleSection fileId="f1" ip="10.0.2.15" />)
    await waitFor(() => expect(screen.getByTestId('host-honeypot-role')).toHaveTextContent('Not a honeypot'))
    expect(screen.getByTestId('host-honeypot-role')).toHaveTextContent('None: only an analyst’s word.')
    expect(screen.queryByTestId('honeypot-undetermined')).not.toBeInTheDocument()
  })

  it('names a honeypot the signatures found', async () => {
    serve({
      label: 'Honeypot', honeypot: 'Cowrie', described: '10.0.2.15 is a Cowrie honeypot', confidence: 60,
      signals: [{ source: 'signature', id: 'cowrie-ssh', honeypot: 'Cowrie', strength: 'STRONG', points: 45, text: "Cowrie's default SSH banner" }],
    })
    render(<HoneypotRoleSection fileId="f1" ip="10.0.2.15" />)
    expect(await screen.findByText('Honeypot (Cowrie)')).toBeInTheDocument()
    expect(screen.getByTestId('honeypot-signals')).toHaveTextContent("Cowrie's default SSH banner")
  })
})
