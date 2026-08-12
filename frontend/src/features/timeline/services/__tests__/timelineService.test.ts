/**
 * The timeline service is the only place the backend's two timestamp encodings are
 * reconciled: Jackson serialises a `LocalDateTime` as an ISO string when the JavaTimeModule
 * is configured and as a `[y, m, d, h, min, s]` array when it is not. The OpenAPI contract
 * optimistically declares `string`, so the type guards cannot catch a regression here — only
 * a test can.
 *
 * It is also the one service that builds a request from derived values (epoch millis → ISO),
 * which is where a wrong conversion produces an empty chart rather than an error.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { timelineService } from '../timelineService'

const FILE_ID = '11111111-1111-1111-1111-111111111111'

/** One bucket as the backend sends it, with the timestamp encoding left to the caller. */
function bucket(timestamp: string | number[]) {
  return { timestamp, packetCount: 12, bytes: 3400, protocols: { TCP: 10, UDP: 2 } }
}

describe('timelineService', () => {
  describe('getTimelineData', () => {
    it('maps the backend buckets onto timeline points', async () => {
      server.use(
        http.get('*/api/v1/timeline/:fileId', () =>
          HttpResponse.json([bucket('2026-08-12T10:30:00')])
        )
      )

      const [point] = await timelineService.getTimelineData(FILE_ID)

      expect(point.packetCount).toBe(12)
      expect(point.bytes).toBe(3400)
      expect(point.protocols).toEqual({ TCP: 10, UDP: 2 })
      expect(Number.isFinite(point.timestamp)).toBe(true)
    })

    it('accepts an array-encoded timestamp as well as an ISO string', async () => {
      // Jackson emits [2026, 8, 12, 10, 30] for a LocalDateTime without the JavaTimeModule.
      // Both encodings must land on the same instant, or the chart silently shifts.
      server.use(
        http.get('*/api/v1/timeline/:fileId', () =>
          HttpResponse.json([bucket([2026, 8, 12, 10, 30])])
        )
      )
      const [fromArray] = await timelineService.getTimelineData(FILE_ID)

      server.use(
        http.get('*/api/v1/timeline/:fileId', () =>
          HttpResponse.json([bucket('2026-08-12T10:30:00')])
        )
      )
      const [fromString] = await timelineService.getTimelineData(FILE_ID)

      expect(fromArray.timestamp).toBe(fromString.timestamp)
    })

    it('forwards the bucketing parameters', async () => {
      let params: URLSearchParams | null = null
      server.use(
        http.get('*/api/v1/timeline/:fileId', ({ request }) => {
          params = new URL(request.url).searchParams
          return HttpResponse.json([])
        })
      )

      await timelineService.getTimelineData(FILE_ID, 60, 500)

      expect(params!.get('interval')).toBe('60')
      expect(params!.get('maxDataPoints')).toBe('500')
    })

    it('omits parameters that were not supplied', async () => {
      let url: URL | null = null
      server.use(
        http.get('*/api/v1/timeline/:fileId', ({ request }) => {
          url = new URL(request.url)
          return HttpResponse.json([])
        })
      )

      await timelineService.getTimelineData(FILE_ID)

      // Sending `interval=undefined` as a literal string would make the backend parse it and
      // fail, rather than falling back to its own default.
      expect(url!.searchParams.has('interval')).toBe(false)
      expect(url!.searchParams.has('maxDataPoints')).toBe(false)
    })

    it('rejects on a server error rather than yielding an empty chart', async () => {
      server.use(
        http.get('*/api/v1/timeline/:fileId', () =>
          HttpResponse.json({ message: 'boom' }, { status: 500 })
        )
      )

      await expect(timelineService.getTimelineData(FILE_ID)).rejects.toThrow()
    })
  })

  describe('getTimelineRange', () => {
    it('converts epoch millis to the ISO-8601 the backend parses', async () => {
      let params: URLSearchParams | null = null
      server.use(
        http.get('*/api/v1/timeline/:fileId/range', ({ request }) => {
          params = new URL(request.url).searchParams
          return HttpResponse.json([])
        })
      )

      const start = Date.UTC(2026, 7, 12, 10, 0, 0)
      const end = Date.UTC(2026, 7, 12, 11, 0, 0)
      await timelineService.getTimelineRange(FILE_ID, start, end)

      // TimelineController parses these with LocalDateTime, so the format is load-bearing —
      // a raw epoch number here is a 400 the chart reports as "no data".
      expect(params!.get('start')).toBe('2026-08-12T10:00:00.000Z')
      expect(params!.get('end')).toBe('2026-08-12T11:00:00.000Z')
    })

    it('maps range results through the same transform', async () => {
      server.use(
        http.get('*/api/v1/timeline/:fileId/range', () =>
          HttpResponse.json([bucket([2026, 8, 12, 10, 30])])
        )
      )

      const [point] = await timelineService.getTimelineRange(FILE_ID, 0, 1)

      expect(point.packetCount).toBe(12)
      expect(Number.isFinite(point.timestamp)).toBe(true)
    })
  })
})
