/**
 * How a hostname was discovered decides how far to trust it. A DHCP option-12 name is whatever
 * the host claimed about itself and is trivially spoofed; a reverse-DNS name came from the
 * resolver. The badge exists so an analyst can tell those apart at a glance, which makes the
 * label mapping the whole contract.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { HostnameSourceBadge } from '../HostnameSourceBadge'

describe('HostnameSourceBadge', () => {
  it.each([
    ['dhcp', 'DHCP'],
    ['mdns', 'mDNS'],
    ['nbns', 'NBNS'],
    ['reverse_dns', 'rDNS'],
    ['manual', 'Manual'],
  ])('labels %s as %s', (source, label) => {
    render(<HostnameSourceBadge source={source} />)

    // The abbreviations are not interchangeable: rDNS and mDNS differ by one character and by
    // who asserted the name.
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('explains the provenance when clicked, not through a native tooltip (#812)', async () => {
    render(<HostnameSourceBadge source="dhcp" />)

    // The chip is four characters; the popover is where the caveat lives. A real button, so it
    // works from a keyboard and on touch, which title= never did.
    const chip = screen.getByRole('button', { name: /DHCP/ })
    expect(chip).not.toHaveAttribute('title')
    await userEvent.click(chip)
    expect(await screen.findByText(/DHCP request \(option 12\)/)).toBeInTheDocument()
  })

  it.each([undefined, null, ''])('renders nothing for %s', source => {
    const { container } = render(<HostnameSourceBadge source={source} />)

    // Most hosts have no discovered name. An empty chip beside every one of them would be
    // noise on the densest screen in the app.
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing for a source it does not recognise', () => {
    const { container } = render(<HostnameSourceBadge source="llmnr" />)

    // Deliberately unlike GeoSourceBadge, which falls back to its cautious label. Here there is
    // no safe default: inventing an abbreviation for an unknown mechanism would assert a
    // provenance nobody established. Showing nothing says "unknown" honestly.
    expect(container).toBeEmptyDOMElement()
  })
})
