/**
 * Entity notes are operator-authored evidence attached to an IP, device, protocol or app.
 * Losing one silently is worse than failing loudly: the note is the analyst's own record of
 * why a host was judged the way it was.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { entityNotesService } from '../entityNotesService'

const note = {
  entityType: 'IP' as const,
  entityKey: '10.0.0.1',
  note: 'DNS server for the branch office',
  createdAt: '2026-08-12T00:00:00Z',
  updatedAt: '2026-08-12T00:00:00Z',
}

describe('entityNotesService', () => {
  it('returns the stored note', async () => {
    server.use(http.get('*/api/v1/entity-notes', () => HttpResponse.json(note)))

    await expect(entityNotesService.getNote('IP', '10.0.0.1')).resolves.toEqual(note)
  })

  it('upserts through PUT, carrying the entity identity in the body', async () => {
    let body: unknown = null
    let method: string | null = null
    server.use(
      http.put('*/api/v1/entity-notes', async ({ request }) => {
        method = request.method
        body = await request.json()
        return HttpResponse.json(note)
      })
    )

    await entityNotesService.upsertNote('IP', '10.0.0.1', 'DNS server for the branch office')

    // PUT rather than POST: upsert is idempotent, so re-saving a note must not create a
    // second one (CLAUDE.md: PUT/PATCH update).
    expect(method).toBe('PUT')
    expect(body).toEqual({
      entityType: 'IP',
      entityKey: '10.0.0.1',
      note: 'DNS server for the branch office',
    })
  })

  it('passes the entity identity as query parameters when reading', async () => {
    let query: URLSearchParams | null = null
    server.use(
      http.get('*/api/v1/entity-notes', ({ request }) => {
        query = new URL(request.url).searchParams
        return HttpResponse.json(note)
      })
    )

    await entityNotesService.getNote('DEVICE', 'aa:bb:cc:dd:ee:ff')

    expect(query!.get('entityType')).toBe('DEVICE')
    // A MAC contains colons, which must survive encoding or the note is read for the wrong key.
    expect(query!.get('entityKey')).toBe('aa:bb:cc:dd:ee:ff')
  })

  it('reads the history list for an entity', async () => {
    const history = [
      {
        fileId: 'f1',
        fileName: 'a.pcap',
        startTime: null,
        endTime: null,
        packetCount: null,
        totalBytes: null,
      },
    ]
    server.use(http.get('*/api/v1/entity-notes/history', () => HttpResponse.json(history)))

    await expect(entityNotesService.getHistory('IP', '10.0.0.1')).resolves.toEqual(history)
  })

  describe('known looseness — pinned, not endorsed', () => {
    it('turns a server error into "no note" instead of surfacing it', async () => {
      let handled = false
      server.use(
        http.get('*/api/v1/entity-notes', () => {
          handled = true
          return HttpResponse.json({ message: 'boom' }, { status: 500 })
        })
      )

      // The catch names a 204 but returns null for *every* error, so an outage is
      // indistinguishable from "this entity has no note". An operator opening a host during a
      // backend failure sees an empty note field and may overwrite a note that still exists.
      await expect(entityNotesService.getNote('IP', '10.0.0.1')).resolves.toBeNull()
      expect(handled, 'the request never reached the handler').toBe(true)
    })

    it('also swallows a 404', async () => {
      server.use(
        http.get('*/api/v1/entity-notes', () =>
          HttpResponse.json({ message: 'gone' }, { status: 404 })
        )
      )

      await expect(entityNotesService.getNote('IP', '10.0.0.1')).resolves.toBeNull()
    })
  })

  it('propagates a failed delete rather than reporting success', async () => {
    let handled = false
    server.use(
      http.delete('*/api/v1/entity-notes', () => {
        handled = true
        return HttpResponse.json({ message: 'nope' }, { status: 500 })
      })
    )

    // Unlike getNote, delete has no catch — so a failure is visible, which is what lets the UI
    // avoid telling the analyst their note was removed when it was not.
    await expect(entityNotesService.deleteNote('IP', '10.0.0.1')).rejects.toThrow()
    expect(handled).toBe(true)
  })
})
