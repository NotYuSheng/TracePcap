/**
 * The conversation table is the primary data view, and this is its fetch path: query building,
 * the paged envelope, and the row transform that turns backend DTOs into what the table renders.
 *
 * `getExportUrl` (covered separately) must produce the *same* filtering as this call — an export
 * that quietly disagrees with the table on screen is worse than one that fails.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import type { ConversationFilters } from '../../types'
import { conversationService } from '../conversationService'

const FILE = '11111111-1111-1111-1111-111111111111'

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

const row = {
  conversationId: 'c1',
  srcIp: '10.0.0.1',
  srcPort: 1234,
  dstIp: '8.8.8.8',
  dstPort: 53,
  protocol: 'UDP',
  packetCount: 4,
  totalBytes: 400,
}

/** Captures the query the service sent and replies with one page of results. */
function captureFetch(body?: Record<string, unknown>) {
  const seen: { query?: URLSearchParams } = {}
  server.use(
    http.get('*/api/v1/conversations/*', ({ request }) => {
      seen.query = new URL(request.url).searchParams
      return HttpResponse.json(
        body ?? { data: [row], page: 1, pageSize: 25, total: 1, totalPages: 1 }
      )
    })
  )
  return seen
}

describe('conversationService.getConversations', () => {
  it('passes the paged envelope through unchanged', async () => {
    captureFetch({ data: [], page: 3, pageSize: 50, total: 120, totalPages: 3 })

    const result = await conversationService.getConversations(FILE, filters())

    // The table's pagination reads these directly; a renamed field would break every page
    // control at once (guarded at compile time too by contractConformance.test-d.ts).
    expect(result).toMatchObject({ page: 3, pageSize: 50, total: 120, totalPages: 3 })
  })

  it('reshapes each row into the endpoint pair the table renders', async () => {
    captureFetch()

    const result = await conversationService.getConversations(FILE, filters())

    expect(result.data[0].id).toBe('c1')
    expect(result.data[0].endpoints).toEqual([
      { ip: '10.0.0.1', port: 1234 },
      { ip: '8.8.8.8', port: 53 },
    ])
  })

  it('defaults a missing port to 0 rather than leaving it undefined', async () => {
    captureFetch({
      data: [{ ...row, srcPort: null, dstPort: null }],
      page: 1,
      pageSize: 25,
      total: 1,
      totalPages: 1,
    })

    const result = await conversationService.getConversations(FILE, filters())

    // ICMP has no ports. The table sorts on this field, so undefined would order unpredictably.
    expect(result.data[0].endpoints.map(e => e.port)).toEqual([0, 0])
  })

  it('defaults absent risk and signature lists to arrays', async () => {
    captureFetch()

    const result = await conversationService.getConversations(FILE, filters())

    // The row renders badges by mapping these; undefined would throw mid-table.
    expect(result.data[0].flowRisks).toEqual([])
    expect(result.data[0].suricataAlerts).toEqual([])
    expect(result.data[0].detectedFileTypes).toEqual([])
  })

  it('always sends page and pageSize, even at their defaults', async () => {
    const seen = captureFetch()

    await conversationService.getConversations(FILE, filters())

    // Deliberately unlike getExportUrl, which omits defaults to keep shared links short. Here
    // the backend needs an explicit page size, so omitting it would let its default win and
    // return a different number of rows than the UI expects.
    expect(seen.query!.get('page')).toBe('1')
    expect(seen.query!.get('pageSize')).toBe('25')
  })

  it('serialises list filters the same way the export URL does', async () => {
    const seen = captureFetch()

    await conversationService.getConversations(
      FILE,
      filters({ protocols: ['TCP', 'UDP'], hasRisks: true })
    )

    expect(seen.query!.get('protocols')).toBe('TCP,UDP')
    expect(seen.query!.get('hasRisks')).toBe('true')
  })

  it('omits sortDir unless a sort field is chosen', async () => {
    const seen = captureFetch()

    await conversationService.getConversations(FILE, filters({ sortDir: 'desc' }))

    // Matches the export builder and the filter hook: a direction with no field means nothing.
    expect(seen.query!.has('sortDir')).toBe(false)
  })

  it('surfaces a failed page fetch rather than resolving empty', async () => {
    let handled = false
    server.use(
      http.get('*/api/v1/conversations/*', () => {
        handled = true
        return HttpResponse.json({ message: 'boom' }, { status: 500 })
      })
    )

    // An empty resolve would render "no conversations" for a capture that has thousands.
    await expect(conversationService.getConversations(FILE, filters())).rejects.toThrow()
    expect(handled).toBe(true)
  })
})
