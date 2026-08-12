/**
 * Entity notes are operator-written annotations on hosts and protocols — the one place a human
 * puts findings back into the tool. Losing one silently is worse than failing loudly.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { entityNotesService } from '../entityNotesService'

const NOTE = {
  entityType: 'IP' as const,
  entityKey: '10.0.0.1',
  note: 'Jump box',
  createdAt: '2026-08-12T00:00:00Z',
  updatedAt: '2026-08-12T00:00:00Z',
}

describe('entityNotesService', () => {
  it('returns the note when one exists', async () => {
    server.use(http.get('*/api/v1/entity-notes', () => HttpResponse.json(NOTE)))
    await expect(entityNotesService.getNote('IP', '10.0.0.1')).resolves.toEqual(NOTE)
  })

  it('sends the entity as query parameters', async () => {
    let params: URLSearchParams | null = null
    server.use(
      http.get('*/api/v1/entity-notes', ({ request }) => {
        params = new URL(request.url).searchParams
        return HttpResponse.json(NOTE)
      })
    )

    await entityNotesService.getNote('DEVICE', 'aa:bb:cc:dd:ee:ff')

    expect(params!.get('entityType')).toBe('DEVICE')
    // A MAC address contains colons, which must survive encoding or the lookup silently misses.
    expect(params!.get('entityKey')).toBe('aa:bb:cc:dd:ee:ff')
  })

  it('swallows a server error and reports "no note" — pinned, not endorsed', async () => {
    // The catch reads `if (status === 204) return null; return null;` — the condition is dead
    // code, so every failure becomes an absent note. An operator whose note failed to load sees
    // an empty box and may overwrite it. Pinned so fixing it is a visible, deliberate change.
    server.use(
      http.get('*/api/v1/entity-notes', () => HttpResponse.json({ message: 'boom' }, { status: 500 }))
    )
    await expect(entityNotesService.getNote('IP', '10.0.0.1')).resolves.toBeNull()
  })

  it('upserts through PUT and returns the saved note', async () => {
    let body: unknown = null
    server.use(
      http.put('*/api/v1/entity-notes', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json(NOTE)
      })
    )

    await expect(entityNotesService.upsertNote('IP', '10.0.0.1', 'Jump box')).resolves.toEqual(NOTE)
    expect(body).toEqual({ entityType: 'IP', entityKey: '10.0.0.1', note: 'Jump box' })
  })

  it('propagates a failed save rather than pretending it worked', async () => {
    // Unlike getNote, a failed write must reject: silently discarding an operator's note is the
    // worst outcome this module can produce.
    server.use(
      http.put('*/api/v1/entity-notes', () => HttpResponse.json({ message: 'nope' }, { status: 500 }))
    )
    await expect(entityNotesService.upsertNote('IP', '10.0.0.1', 'x')).rejects.toThrow()
  })
})
