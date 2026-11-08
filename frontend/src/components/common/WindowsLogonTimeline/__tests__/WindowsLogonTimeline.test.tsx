/**
 * The host login timeline (#812). A host can have several Windows accounts over one capture, so
 * this lists them all, oldest first, in words an analyst can act on without reading CN=/OU= syntax.
 */
import { render, screen } from '@testing-library/react'
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { WindowsLogonTimeline } from '../WindowsLogonTimeline'

const FILE = '11111111-1111-1111-1111-111111111111'

function serve(rows: unknown[]) {
  server.use(http.get('*/files/:fileId/hosts/:ip/windows-logons', () => HttpResponse.json(rows)))
}

const alice = {
  username: 'alice', evidence: 'kerberos_as_req', seenCount: 1, candidateOnly: false,
  firstSeen: '2026-11-01T09:02:00', lastSeen: '2026-11-01T09:02:00',
}
const bob = {
  username: 'bob', evidence: 'kerberos_as_req', seenCount: 2, candidateOnly: false,
  firstSeen: '2026-11-01T14:15:00', lastSeen: '2026-11-01T14:16:00',
}
const dana = {
  username: 'Dana Lee', evidence: 'ldap_dn', seenCount: 1, candidateOnly: true,
  directoryEntry: 'CN=Dana Lee,OU=Sales,OU=Staff,DC=example,DC=com',
  folder: 'Staff / Sales', folderKind: 'CUSTOM', domain: 'example.com',
  firstSeen: '2026-11-01T11:40:00', lastSeen: '2026-11-01T11:40:00',
}

describe('WindowsLogonTimeline', () => {
  it('lists every account in order, with evidence in words', async () => {
    serve([alice, dana, bob])
    render(<WindowsLogonTimeline fileId={FILE} ip="10.0.0.10" deviceType="LAPTOP_DESKTOP" />)

    const items = await screen.findAllByRole('listitem')
    expect(items.map(li => li.querySelector('strong')?.textContent)).toEqual(['alice', 'Dana Lee', 'bob'])
    expect(screen.getAllByText('Signed in (Kerberos login)')).toHaveLength(2)
    expect(screen.getByText('Looked up (LDAP directory)')).toBeInTheDocument()
    expect(screen.getByText('Seen 2 times', { exact: false })).toBeInTheDocument()
  })

  it('explains a custom folder in plain words, and keeps the raw entry for experts', async () => {
    serve([dana])
    render(<WindowsLogonTimeline fileId={FILE} ip="10.0.0.12" />)

    expect(
      await screen.findByText(/Custom folder "Staff \/ Sales", domain example.com\. Could be a person, a computer or a group\./)
    ).toBeInTheDocument()
    expect(screen.getByText('Not used by default')).toBeInTheDocument()
    expect(screen.getByText('CN=Dana Lee,OU=Sales,OU=Staff,DC=example,DC=com')).toBeInTheDocument()
  })

  it('says why LDAP lookups are not used on a server', async () => {
    serve([{ ...dana, folder: 'Users', folderKind: 'USERS', candidateOnly: false }])
    render(<WindowsLogonTimeline fileId={FILE} ip="10.0.0.1" deviceType="SERVER" />)

    expect(await screen.findByText(/classified as a server or router/)).toBeInTheDocument()
  })

  it('renders nothing when no accounts were seen', async () => {
    serve([])
    const { container } = render(<WindowsLogonTimeline fileId={FILE} ip="10.0.0.99" />)

    await new Promise(r => setTimeout(r, 50))
    expect(container).toBeEmptyDOMElement()
  })
})
