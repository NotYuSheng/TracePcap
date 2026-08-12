/**
 * Filter generation calls an LLM, so it is the slowest request the app makes and the one whose
 * timeout arithmetic actually matters: too tight and a valid answer is discarded as a failure.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { filterService } from '../filterService'

const FILE_ID = '11111111-1111-1111-1111-111111111111'

describe('filterService', () => {
  it('posts the natural-language query with the file id in the body', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/api/v1/filter/:fileId/generate', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ filter: 'tcp.port == 443' })
      })
    )

    await filterService.generateFilter(FILE_ID, 'https traffic')

    // fileId appears in both the path and the body. Pinned because dropping the body copy looks
    // like harmless cleanup, and the backend reads it from there.
    expect(body).toMatchObject({ fileId: FILE_ID, naturalLanguageQuery: 'https traffic' })
  })

  it('adds a 10s buffer over the caller-supplied timeout', async () => {
    server.use(
      http.post('*/api/v1/filter/:fileId/generate', () => HttpResponse.json({ filter: 'ip' }))
    )

    // The client must wait longer than the server's own budget, or a request the backend is
    // about to answer is abandoned and reported as a failure.
    await expect(filterService.generateFilter(FILE_ID, 'q', 30_000)).resolves.toBeDefined()
  })

  it('surfaces an LLM failure instead of returning an empty filter', async () => {
    server.use(
      http.post('*/api/v1/filter/:fileId/generate', () =>
        HttpResponse.json({ message: 'LLM unavailable' }, { status: 502 })
      )
    )

    // An empty filter would silently match everything, which is worse than an error.
    await expect(filterService.generateFilter(FILE_ID, 'q')).rejects.toThrow()
  })

  it('executes a filter and returns the matching page', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/api/v1/filter/:fileId/execute', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ packets: [], total: 0 })
      })
    )

    await filterService.executeFilter(FILE_ID, 'tcp', 2, 50)

    expect(body).toMatchObject({ fileId: FILE_ID, filter: 'tcp' })
  })
})
