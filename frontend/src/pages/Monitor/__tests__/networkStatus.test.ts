/** Monitor B: one status per network, its next action, and the capture track's colours. */
import { describe, expect, it } from 'vitest'

import type { CaptureMark, Network } from '@/features/monitor/types/monitor.types'
import { markTone, matchesFilter, networkStatus } from '../networkStatus'

const net = (extra: Partial<Network> = {}): Network => ({
  id: 'n1',
  name: 'Staff Wi-Fi',
  description: null,
  snapshotCount: 2,
  criticalChanges: 0,
  warningChanges: 0,
  hasInsights: false,
  createdAt: '',
  updatedAt: '',
  ...extra,
})

describe('networkStatus', () => {
  it('asks for the first capture when there is none', () => {
    expect(networkStatus(net({ snapshotCount: 0 }))).toMatchObject({
      key: 'empty',
      label: 'No captures yet',
      action: 'Add the first capture',
      to: '/monitor/n1?add=1',
    })
  })

  it('puts critical changes before warnings', () => {
    expect(networkStatus(net({ criticalChanges: 2, warningChanges: 1 })).label).toBe('2 critical to review')
    expect(networkStatus(net({ warningChanges: 1 }))).toMatchObject({
      key: 'review',
      label: '1 change to review',
      action: 'Review',
    })
  })

  it('calls a single capture the baseline, and offers the next one', () => {
    expect(networkStatus(net({ snapshotCount: 1 }))).toMatchObject({ key: 'baseline', action: 'Add a capture' })
  })

  it('is up to date when nothing is waiting', () => {
    expect(networkStatus(net())).toMatchObject({ key: 'clear', label: 'Up to date', action: 'Open' })
  })
})

describe('filters and track', () => {
  it('filters by what needs review and by no captures', () => {
    expect(matchesFilter(net({ warningChanges: 1 }), 'review')).toBe(true)
    expect(matchesFilter(net({ criticalChanges: 1 }), 'review')).toBe(true)
    expect(matchesFilter(net(), 'review')).toBe(false)
    expect(matchesFilter(net({ snapshotCount: 0 }), 'empty')).toBe(true)
  })

  it('colours each capture by its worst change, the first as the baseline', () => {
    const m = (extra: Partial<CaptureMark>): CaptureMark => ({
      snapshotId: 's',
      fileName: 'a.pcap',
      capturedAt: null,
      baseline: false,
      changes: 'NONE',
      ...extra,
    })
    expect(markTone(m({ baseline: true, changes: 'WARNING' }))).toBe('baseline')
    expect(markTone(m({ changes: 'WARNING' }))).toBe('warning')
    expect(markTone(m({ changes: 'CRITICAL' }))).toBe('critical')
    expect(markTone(m({ changes: 'INFO' }))).toBe('none')
  })
})
