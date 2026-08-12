/**
 * The conversation export URLs are the #630 affordance class: they are navigated by the
 * browser directly, so they bypass `apiClient` and must carry the `/api/v1` prefix themselves.
 * That is exactly what the extracted-file download got wrong and shipped broken for months.
 *
 * They are pure builders, so no HTTP is involved — which is the point. A wrong URL here fails
 * as a browser download that never starts, with nothing in the console.
 */
import { describe, expect, it } from 'vitest'

import type { ConversationFilters } from '../../types'
import { conversationService } from '../conversationService'

const FILE_ID = '11111111-1111-1111-1111-111111111111'

function filters(overrides: Partial<ConversationFilters> = {}): ConversationFilters {
  return {
    ip: '',
    port: '',
    payloadContains: '',
    protocols: [],
    l7Protocols: [],
    apps: [],
    categories: [],
    hasRisks: false,
    fileTypes: [],
    riskTypes: [],
    customSignatures: [],
    suricataAlerts: [],
    deviceTypes: [],
    countries: [],
    sortBy: '' as ConversationFilters['sortBy'],
    sortDir: 'asc',
    page: 1,
    pageSize: 25,
    ...overrides,
  }
}

describe('conversation export URLs', () => {
  it('carries the version segment the browser will not add', () => {
    const url = conversationService.getExportUrl(FILE_ID, filters())

    // The #630 assertion. Anything served from /api/... without /v1 is a 404 the user sees as
    // "download failed", with no error anywhere in the app.
    expect(url.startsWith('/api/v1/')).toBe(true)
  })

  it('omits the query string entirely when no filters are set', () => {
    const url = conversationService.getExportUrl(FILE_ID, filters())

    // A bare "?" would be harmless but is worth pinning: the builder appends it conditionally.
    expect(url).not.toContain('?')
  })

  it('serialises list filters as comma-joined values', () => {
    const url = conversationService.getExportUrl(
      FILE_ID,
      filters({ protocols: ['TCP', 'UDP'], countries: ['SG', 'US'] })
    )
    const query = new URLSearchParams(url.split('?')[1])

    expect(query.get('protocols')).toBe('TCP,UDP')
    expect(query.get('countries')).toBe('SG,US')
  })

  it('sends hasRisks only when true', () => {
    const off = new URLSearchParams(conversationService.getExportUrl(FILE_ID, filters()).split('?')[1])
    const on = new URLSearchParams(
      conversationService.getExportUrl(FILE_ID, filters({ hasRisks: true })).split('?')[1]
    )

    expect(off.has('hasRisks')).toBe(false)
    expect(on.get('hasRisks')).toBe('true')
  })

  it('omits sortDir unless a sort field is chosen', () => {
    const noSort = conversationService.getExportUrl(FILE_ID, filters({ sortDir: 'desc' }))
    const sorted = conversationService.getExportUrl(
      FILE_ID,
      filters({ sortBy: 'startTime' as ConversationFilters['sortBy'], sortDir: 'desc' })
    )

    // Same rule the filter hook enforces: a direction without a field means nothing, and the
    // export must match what the table is showing.
    expect(noSort).not.toContain('sortDir')
    expect(sorted).toContain('sortDir=desc')
  })

  it('encodes a payload search containing URL-significant characters', () => {
    const url = conversationService.getExportUrl(
      FILE_ID,
      filters({ payloadContains: 'a&b=c d' })
    )
    const query = new URLSearchParams(url.split('?')[1])

    // Unencoded, "&" would split into a second parameter and silently change the export.
    expect(query.get('payloadContains')).toBe('a&b=c d')
  })

  it('builds the single-conversation pcap URL under the version prefix', () => {
    const url = conversationService.getConversationPcapExportUrl('conv-9')

    expect(url.startsWith('/api/v1/')).toBe(true)
    expect(url).toContain('conv-9')
  })

  it('builds the filtered pcap export URL under the version prefix', () => {
    const url = conversationService.getPcapExportUrl(FILE_ID, filters({ protocols: ['TCP'] }))

    expect(url.startsWith('/api/v1/')).toBe(true)
    expect(new URLSearchParams(url.split('?')[1]).get('protocols')).toBe('TCP')
  })
})
