/**
 * The analysis summary is the first screen after an upload, and this service is where the
 * backend DTO becomes the frontend model. It is dense with `||` and `??` defaults, which
 * differ precisely where it matters: `||` also replaces 0 and "".
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { analysisService } from '../analysisService'

const FILE_ID = '11111111-1111-1111-1111-111111111111'

function respondWith(summary: Record<string, unknown>) {
  server.use(
    http.get('*/api/v1/analysis/:fileId/summary', () => HttpResponse.json(summary))
  )
}

describe('analysisService.getAnalysisSummary', () => {
  it('maps a conversation onto the endpoint-pair shape the UI renders', async () => {
    respondWith({
      fileId: FILE_ID,
      timeRange: [1000, 2000],
      topConversations: [
        {
          id: 'c1',
          srcIp: '10.0.0.1',
          srcPort: 1234,
          dstIp: '8.8.8.8',
          dstPort: 53,
          protocol: 'UDP',
          packetCount: 4,
          totalBytes: 400,
        },
      ],
    })

    const result = await analysisService.getAnalysisSummary(FILE_ID)

    expect(result.topConversations[0].endpoints).toEqual([
      { ip: '10.0.0.1', port: 1234 },
      { ip: '8.8.8.8', port: 53 },
    ])
    expect(result.topConversations[0].protocol).toEqual({ name: 'UDP', layer: 'Transport' })
  })

  it('defaults absent collections to empty arrays rather than undefined', async () => {
    respondWith({ fileId: FILE_ID })

    const result = await analysisService.getAnalysisSummary(FILE_ID)

    // The overview maps over these directly; undefined would throw on first render.
    expect(result.topConversations).toEqual([])
    expect(result.protocolDistribution).toEqual([])
    expect(result.uniqueHosts).toEqual([])
  })

  it('preserves a zero packet count rather than treating it as missing', async () => {
    respondWith({
      fileId: FILE_ID,
      totalPackets: 0,
      topConversations: [{ id: 'c1', srcIp: 'a', dstIp: 'b', packetCount: 0, totalBytes: 0 }],
    })

    const result = await analysisService.getAnalysisSummary(FILE_ID)

    // A genuinely empty capture must read as 0, not as absent data.
    expect(result.totalPackets).toBe(0)
    expect(result.topConversations[0].packetCount).toBe(0)
  })

  it('substitutes a placeholder file name when the backend omits one', async () => {
    respondWith({ fileId: FILE_ID })

    const result = await analysisService.getAnalysisSummary(FILE_ID)

    expect(result.fileName).toBe('unknown.pcap')
  })

  it('keeps risk and signature lists as arrays when the backend sends null', async () => {
    respondWith({
      fileId: FILE_ID,
      topConversations: [
        { id: 'c1', srcIp: 'a', dstIp: 'b', flowRisks: null, suricataAlerts: null },
      ],
    })

    const result = await analysisService.getAnalysisSummary(FILE_ID)

    // `?? []` rather than `|| []`, so these survive null without collapsing anything falsy.
    expect(result.topConversations[0].flowRisks).toEqual([])
    expect(result.topConversations[0].suricataAlerts).toEqual([])
  })

  describe('known looseness — pinned, not endorsed', () => {
    it('replaces an epoch-zero start time with the current time', async () => {
      respondWith({ fileId: FILE_ID, timeRange: [0, 0] })

      const before = Date.now()
      const result = await analysisService.getAnalysisSummary(FILE_ID)

      // `timeRange?.[0] || Date.now()` — `||` treats a legitimate epoch-0 timestamp as missing,
      // so a capture timestamped at the epoch is displayed as happening now. `??` would not.
      expect(result.timeRange[0]).toBeGreaterThanOrEqual(before)
    })
  })

  it('surfaces a failed summary fetch', async () => {
    let handled = false
    server.use(
      http.get('*/api/v1/analysis/:fileId/summary', () => {
        handled = true
        return HttpResponse.json({ message: 'not ready' }, { status: 409 })
      })
    )

    await expect(analysisService.getAnalysisSummary(FILE_ID)).rejects.toThrow()
    expect(handled, 'the summary endpoint was never reached').toBe(true)
  })
})
