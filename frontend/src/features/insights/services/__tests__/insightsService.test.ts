/**
 * Node roles are the operator's persistent labels for hosts — they feed monitor mode and the
 * graph. The suggestion endpoints are LLM-backed and answer 422 when there is not enough
 * evidence, which is a normal outcome an analyst must be able to read, not a crash.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { insightsService } from '../insightsService'

const FILE = '11111111-1111-1111-1111-111111111111'

describe('insightsService', () => {
  describe('getNodeRole', () => {
    it('returns null when no role is set', async () => {
      server.use(http.get('*/node-roles', () => new HttpResponse(null, { status: 404 })))

      await expect(insightsService.getNodeRole('IP', '10.0.0.1', FILE)).resolves.toBeNull()
    })

    it('rethrows a server error rather than reporting "no role"', async () => {
      let handled = false
      server.use(
        http.get('*/node-roles', () => {
          handled = true
          return HttpResponse.json({ message: 'boom' }, { status: 500 })
        })
      )

      // Same correct shape as adjudicationService, and the opposite of
      // entityNotesService.getNote — an outage must not read as "this host has no role".
      await expect(insightsService.getNodeRole('IP', '10.0.0.1', FILE)).rejects.toThrow()
      expect(handled).toBe(true)
    })
  })

  it('defaults a null role list to an empty array', async () => {
    server.use(http.get('*/files/*/node-roles', () => HttpResponse.json(null)))

    // `r.data ?? []` — the graph maps over this to label nodes, so null would throw on render.
    await expect(insightsService.listNodeRoles(FILE)).resolves.toEqual([])
  })

  describe('role suggestion (LLM-backed)', () => {
    it('surfaces the backend message when there is not enough evidence', async () => {
      server.use(
        http.post('*/suggest', () =>
          HttpResponse.json({ message: 'Only 2 conversations seen' }, { status: 422 })
        )
      )

      // 422 is a normal answer, not a fault: the analyst needs to read *why* no role was
      // suggested, so the backend's own wording is preserved rather than replaced.
      await expect(
        insightsService.suggestNodeRole('IP', '10.0.0.1', FILE)
      ).rejects.toThrow('Only 2 conversations seen')
    })

    it('falls back to the error field when message is absent', async () => {
      server.use(
        http.post('*/suggest', () => HttpResponse.json({ error: 'no evidence' }, { status: 422 }))
      )

      await expect(
        insightsService.suggestNodeRole('IP', '10.0.0.1', FILE)
      ).rejects.toThrow('no evidence')
    })

    it('falls back to a readable default when the body carries neither', async () => {
      server.use(http.post('*/suggest', () => HttpResponse.json({}, { status: 422 })))

      // Without this the analyst would see a bare "Request failed with status code 422".
      await expect(
        insightsService.suggestNodeRole('IP', '10.0.0.1', FILE)
      ).rejects.toThrow('Insufficient evidence for a role suggestion.')
    })

    it('leaves a non-422 failure as the original error', async () => {
      let handled = false
      server.use(
        http.post('*/suggest', () => {
          handled = true
          return HttpResponse.json({ message: 'boom' }, { status: 500 })
        })
      )

      // Only 422 is reinterpreted; a real outage keeps its axios error so callers can tell the
      // two apart.
      await expect(insightsService.suggestNodeRole('IP', '10.0.0.1', FILE)).rejects.toThrow()
      expect(handled).toBe(true)
    })

    it('applies the same message handling to the preview variant', async () => {
      server.use(
        http.post('*/suggest-preview', () =>
          HttpResponse.json({ message: 'not enough traffic' }, { status: 422 })
        )
      )

      // The preview pre-fills the editor without persisting, so it hits the same wall and must
      // explain itself the same way.
      await expect(
        insightsService.suggestNodeRolePreview('IP', '10.0.0.1', FILE)
      ).rejects.toThrow('not enough traffic')
    })
  })
})
