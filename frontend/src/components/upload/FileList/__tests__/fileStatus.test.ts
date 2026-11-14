/** One status per capture, and the quiet notes under it. */
import { describe, expect, it } from 'vitest'

import { actionOf, expiresAt, notesOf, statusOf, type StatusContext, type StatusFile } from '../fileStatus'

const NOW = Date.UTC(2026, 10, 14, 12)
const H = 3600_000
const file = (extra: Partial<StatusFile> = {}): StatusFile => ({
  fileId: 'f1',
  status: 'COMPLETED',
  source: 'ANALYSIS',
  uploadedAt: NOW - H,
  enableNdpi: true,
  enableSuricata: true,
  enableFileExtraction: true,
  ...extra,
})
const ctx = (extra: Partial<StatusContext> = {}): StatusContext => ({
  retentionHours: 12,
  keptWith: [],
  rulesChanged: false,
  now: NOW,
  ...extra,
})

describe('statusOf', () => {
  it('maps the backend states', () => {
    expect(statusOf(file({ status: 'UPLOADING' }), ctx()).label).toBe('Queued')
    expect(statusOf(file({ status: 'processing' }), ctx()).label).toBe('Analysing')
    expect(statusOf(file({ status: 'FAILED' }), ctx()).label).toBe('Failed')
    expect(statusOf(file(), ctx()).label).toBe('Ready')
  })

  it('is Expiring soon within two hours of deletion', () => {
    expect(statusOf(file({ uploadedAt: NOW - 10.5 * H }), ctx()).key).toBe('expiring')
    expect(statusOf(file({ uploadedAt: NOW - 9 * H }), ctx()).key).toBe('ready')
  })

  it('never expires when kept with a network, a monitor upload, or retention is off', () => {
    const old = file({ uploadedAt: NOW - 11 * H })
    expect(statusOf(old, ctx({ keptWith: [{ networkId: 'n', networkName: 'Staff Wi-Fi' }] })).key).toBe('ready')
    expect(statusOf({ ...old, source: 'MONITOR' }, ctx()).key).toBe('ready')
    expect(statusOf(old, ctx({ retentionHours: 0 })).key).toBe('ready')
    expect(expiresAt(old, ctx({ retentionHours: null }))).toBeNull()
  })
})

describe('notesOf', () => {
  it('has no notes for a plain full analysis', () => {
    expect(notesOf(file(), ctx())).toEqual([])
  })

  it('names the network a capture is kept with, as a link', () => {
    const [n] = notesOf(file(), ctx({ keptWith: [{ networkId: 'n1', networkName: 'Staff Wi-Fi' }] }))
    expect(n).toMatchObject({ label: 'Kept with Staff Wi-Fi', to: '/monitor/n1', tone: 'kept' })
  })

  it('says which tools were off, without calling it a fault', () => {
    expect(notesOf(file({ enableSuricata: false }), ctx()).map(n => n.label)).toEqual(['Without Suricata'])
    expect(notesOf(file({ enableSuricata: false, enableNdpi: false }), ctx())[0].label).toBe('Without Suricata, nDPI')
  })

  it('notes changed rules and removed packets', () => {
    const labels = notesOf(file({ packetsRemoved: true }), ctx({ rulesChanged: true })).map(n => n.label)
    expect(labels).toEqual(['Rules changed since', 'Packets removed'])
  })
})

describe('actionOf', () => {
  it('offers what each status allows', () => {
    expect(actionOf('ready')).toBe('Open')
    expect(actionOf('analysing')).toBe('Watch')
    expect(actionOf('failed')).toBe('See why')
  })
})
