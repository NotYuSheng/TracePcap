/**
 * Custom private ranges decide whether an IP is treated as internal, which feeds host
 * classification and therefore the graph. A silently-failing write here changes how the whole
 * capture is interpreted.
 *
 * This service is also a blind spot in the #630 guard: it hard-codes its three paths inline
 * instead of going through `API_ENDPOINTS`, so `endpointPaths.test.ts` — which iterates the
 * endpoint maps — never sees them. Until they move into the map, these tests are the only
 * thing checking those URLs, which is why each asserts the path MSW actually received.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { customPrivateRangeService } from '../customPrivateRangeService'

const RANGE = { id: 1, cidr: '10.42.0.0/16', classification: 'PRIVATE' }

describe('customPrivateRangeService', () => {
  it('lists ranges from the versioned collection path', async () => {
    let path: string | null = null
    server.use(
      http.get('*/api/v1/custom-private-ranges', ({ request }) => {
        path = new URL(request.url).pathname
        return HttpResponse.json([RANGE])
      })
    )

    await expect(customPrivateRangeService.list()).resolves.toEqual([RANGE])
    expect(path).toBe('/api/v1/custom-private-ranges')
  })

  it('defaults a new range to PRIVATE', async () => {
    let body: unknown = null
    server.use(
      http.post('*/api/v1/custom-private-ranges', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json(RANGE, { status: 201 })
      })
    )

    await customPrivateRangeService.create('10.42.0.0/16')

    // The default is the whole point of the parameter: an operator adding a range means
    // "treat this as internal" unless they say otherwise.
    expect(body).toEqual({ cidr: '10.42.0.0/16', classification: 'PRIVATE' })
  })

  it('sends an explicit classification when given one', async () => {
    let body: unknown = null
    server.use(
      http.post('*/api/v1/custom-private-ranges', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json({ ...RANGE, classification: 'PUBLIC' }, { status: 201 })
      })
    )

    await customPrivateRangeService.create('203.0.113.0/24', 'PUBLIC')

    expect(body).toEqual({ cidr: '203.0.113.0/24', classification: 'PUBLIC' })
  })

  it('returns the created range rather than the envelope', async () => {
    server.use(
      http.post('*/api/v1/custom-private-ranges', () => HttpResponse.json(RANGE, { status: 201 }))
    )

    await expect(customPrivateRangeService.create('10.42.0.0/16')).resolves.toEqual(RANGE)
  })

  it('deletes by id and tolerates the 204 empty body', async () => {
    let path: string | null = null
    server.use(
      http.delete('*/api/v1/custom-private-ranges/:id', ({ request }) => {
        path = new URL(request.url).pathname
        // 204 with no body, per the API conventions in CLAUDE.md. Parsing that as JSON would
        // throw, so this also pins that the service does not try to read a response.
        return new HttpResponse(null, { status: 204 })
      })
    )

    await expect(customPrivateRangeService.delete(7)).resolves.toBeUndefined()
    expect(path).toBe('/api/v1/custom-private-ranges/7')
  })

  it('rejects when a range is refused rather than reporting success', async () => {
    server.use(
      http.post('*/api/v1/custom-private-ranges', () =>
        HttpResponse.json({ message: 'overlapping range' }, { status: 400 })
      )
    )

    // A swallowed 400 would leave the UI showing a range the backend never stored, and the
    // classification it implies would silently not apply.
    await expect(customPrivateRangeService.create('10.42.0.0/16')).rejects.toThrow()
  })
})
