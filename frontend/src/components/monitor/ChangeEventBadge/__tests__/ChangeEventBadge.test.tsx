/**
 * The first component test in the codebase.
 *
 * A change event row is the sentence an operator reads to decide whether something matters.
 * The wording is not cosmetic: IP_MAC_DRIFT renders either "Potential ARP spoof" or "IP
 * reassignment" from the same change type, depending on which side moved — one is an attack
 * signature, the other is DHCP doing its job.
 */
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types'
import { ChangeEventBadge } from '../ChangeEventBadge'

function event(overrides: Partial<ChangeEvent> = {}): ChangeEvent {
  return {
    id: 'e1',
    changeType: 'MAC_ADDED',
    severity: 'INFO',
    entityKey: 'aa:bb:cc:dd:ee:ff',
    detectedAt: '2026-08-12T10:00:00Z',
    reviewed: false,
    notes: null,
    newValue: {},
    oldValue: {},
    ...overrides,
  } as ChangeEvent
}

const snapshots = [
  { id: 's1', fileName: 'monday.pcap', snapshotOrder: 0 } as NetworkSnapshot,
]

function renderBadge(e: ChangeEvent, onPatch = vi.fn().mockResolvedValue(undefined)) {
  render(<ChangeEventBadge event={e} snapshots={snapshots} onPatch={onPatch} />)
  return { onPatch }
}

describe('ChangeEventBadge', () => {
  describe('IP_MAC_DRIFT wording', () => {
    it('calls a changed MAC on a stable IP a potential ARP spoof', () => {
      renderBadge(
        event({
          changeType: 'IP_MAC_DRIFT',
          entityKey: '10.0.0.1',
          oldValue: { mac: 'aa:aa:aa:aa:aa:aa' },
          newValue: { mac: 'bb:bb:bb:bb:bb:bb' },
        })
      )

      // Same IP, different MAC. This is the wording that makes an analyst look.
      expect(screen.getByText(/Potential ARP spoof/)).toBeInTheDocument()
      expect(screen.getByText(/aa:aa:aa:aa:aa:aa/)).toBeInTheDocument()
    })

    it('calls a changed IP on a stable MAC a reassignment, not a spoof', () => {
      renderBadge(
        event({
          changeType: 'IP_MAC_DRIFT',
          entityKey: 'aa:bb:cc:dd:ee:ff',
          oldValue: { ip: '10.0.0.1' },
          newValue: { ip: '10.0.0.2' },
        })
      )

      // Routine DHCP. Labelling this an ARP spoof would cry wolf on every lease renewal.
      expect(screen.getByText(/IP reassignment/)).toBeInTheDocument()
      expect(screen.queryByText(/ARP spoof/)).not.toBeInTheDocument()
    })
  })

  it('names the device and where it appeared', () => {
    renderBadge(
      event({
        changeType: 'MAC_ADDED',
        entityKey: 'aa:bb:cc:dd:ee:ff',
        newValue: { manufacturer: 'Cisco', deviceType: 'router', ip: '10.0.0.1' },
      })
    )

    expect(screen.getByText(/New device: aa:bb:cc:dd:ee:ff \(Cisco, router\) at 10\.0\.0\.1/))
      .toBeInTheDocument()
  })

  it('omits the parenthetical when nothing is known about the device', () => {
    renderBadge(event({ changeType: 'MAC_ADDED', entityKey: 'aa:bb:cc:dd:ee:ff' }))

    // "New device: aa:… ()" would read as missing data rather than unknown data.
    expect(screen.getByText('New device: aa:bb:cc:dd:ee:ff')).toBeInTheDocument()
  })

  it('distinguishes a VPN appearing from one going away', () => {
    const { unmount } = render(
      <ChangeEventBadge
        event={event({ changeType: 'VPN_DRIFT', newValue: { riskType: 'WireGuard' } })}
        snapshots={snapshots}
        onPatch={vi.fn()}
      />
    )
    expect(screen.getByText(/VPN detected: WireGuard/)).toBeInTheDocument()
    unmount()

    renderBadge(
      event({ changeType: 'VPN_DRIFT', newValue: {}, oldValue: { riskType: 'WireGuard' } })
    )
    expect(screen.getByText(/VPN signal gone: WireGuard/)).toBeInTheDocument()
  })

  it('names the security signal kind rather than saying "security signal"', () => {
    renderBadge(
      event({
        changeType: 'SECURITY_ALERT_ADDED',
        entityKey: '10.0.0.1',
        newValue: { signalKind: 'ids' },
      })
    )

    expect(screen.getByText(/IDS alert appeared: 10\.0\.0\.1/)).toBeInTheDocument()
  })

  it('falls back to the entity key for an unrecognised change type', () => {
    renderBadge(event({ changeType: 'SOMETHING_NEW' as ChangeEvent['changeType'] }))

    // A backend that adds a change type before the frontend knows it still renders something
    // identifiable rather than a blank row.
    expect(screen.getByText('aa:bb:cc:dd:ee:ff')).toBeInTheDocument()
  })

  it('shows which snapshot the change was detected in', () => {
    renderBadge(event({ toSnapshotId: 's1' }))

    // snapshotOrder is zero-based internally and one-based in the UI.
    expect(screen.getByText(/Snapshot 1: monday\.pcap/)).toBeInTheDocument()
  })

  it('flips the state before the save resolves, not after', async () => {
    // Deferred so the assertion lands while the request is still in flight. Asserting only
    // after it resolves cannot tell an optimistic update from a pessimistic one — both end in
    // the same place, and the difference is the whole point of the local state.
    let resolvePatch: () => void = () => {}
    const onPatch = vi.fn(() => new Promise<void>(res => { resolvePatch = () => res() }))
    renderBadge(event(), onPatch)

    await userEvent.click(screen.getByTitle('Mark as reviewed'))

    expect(onPatch).toHaveBeenCalledWith('e1', { reviewed: true })
    // Mid-flight: the row greys out immediately so a triage queue stays responsive.
    expect(screen.getByTitle('Mark as unreviewed')).toBeInTheDocument()

    resolvePatch()
    await waitFor(() => expect(screen.getByTitle('Mark as unreviewed')).toBeInTheDocument())
  })

  it('reverts the review state when the save fails', async () => {
    const onPatch = vi.fn().mockRejectedValue(new Error('offline'))
    renderBadge(event(), onPatch)

    await userEvent.click(screen.getByTitle('Mark as reviewed'))
    await waitFor(() => expect(onPatch).toHaveBeenCalled())

    // Assert the state that actually reverts, not merely that a button exists — an earlier
    // version of this test checked for the button by role and passed with the revert deleted,
    // because the button is present either way. The title is derived from localReviewed, so
    // it is the visible consequence of the rollback.
    //
    // Optimistic UI without a revert leaves the row greyed out as reviewed while the backend
    // still has it outstanding: the operator's triage queue and the truth diverge silently.
    await waitFor(() => expect(screen.getByTitle('Mark as reviewed')).toBeInTheDocument())
    expect(screen.queryByTitle('Mark as unreviewed')).not.toBeInTheDocument()
  })
})
