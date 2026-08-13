/**
 * Human overrides and analyst evidence are the audit trail behind an adjudicated verdict — the
 * record of why a person disagreed with the machine. Every write here causes the backend to
 * re-run adjudication, so a wrong body silently changes a host's identity.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { adjudicationService } from '../adjudicationService'

const FILE = '11111111-1111-1111-1111-111111111111'
const Q = 'host-identity'
const KEY = '10.0.0.1'

const override = {
  question: Q,
  entityKey: KEY,
  label: 'printer',
  rationale: 'banner says so',
  actor: 'analyst',
  createdAt: '2026-08-12T00:00:00Z',
  updatedAt: '2026-08-12T00:00:00Z',
}

describe('adjudicationService', () => {
  describe('getOverride', () => {
    it('returns the stored override', async () => {
      server.use(http.get('*/adjudications/*', () => HttpResponse.json(override)))

      await expect(adjudicationService.getOverride(FILE, Q, KEY)).resolves.toEqual(override)
    })

    it('treats 404 as "no override set"', async () => {
      let handled = false
      server.use(
        http.get('*/adjudications/*', () => {
          handled = true
          return new HttpResponse(null, { status: 404 })
        })
      )

      await expect(adjudicationService.getOverride(FILE, Q, KEY)).resolves.toBeNull()
      expect(handled).toBe(true)
    })

    it('returns an empty string, not null, for a 204 — the catch never sees it', async () => {
      server.use(http.get('*/adjudications/*', () => new HttpResponse(null, { status: 204 })))

      // The catch tests for `status === 204`, but that branch is dead: axios resolves 2xx, so
      // a 204 never throws. `r.data` is '' for an empty body, and that is what callers get
      // despite the declared `AdjudicationOverride | null`.
      //
      // It happens to work today because '' is falsy and every call site does a truthiness
      // check — but a call site written to the signature, e.g. `override?.label`, would read
      // a string's properties instead of hitting the null branch. Pinned, not fixed: the fix
      // is to map a 204 to null, which is a behaviour change for those call sites.
      await expect(adjudicationService.getOverride(FILE, Q, KEY)).resolves.toBe('')
    })

    it('rethrows a server error instead of reporting "no override"', async () => {
      let handled = false
      server.use(
        http.get('*/adjudications/*', () => {
          handled = true
          return HttpResponse.json({ message: 'boom' }, { status: 500 })
        })
      )

      // This is the distinction entityNotesService.getNote misses: it collapses *every* error
      // to null, so an outage reads as "nothing recorded". Here only the two statuses that
      // genuinely mean "absent" are swallowed, and an outage stays visible — which matters
      // because the UI would otherwise offer to create an override on top of one that exists.
      await expect(adjudicationService.getOverride(FILE, Q, KEY)).rejects.toThrow()
      expect(handled).toBe(true)
    })
  })

  it('sends an explicit null rationale rather than omitting the field', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.put('*/adjudications/*', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json(override)
      })
    )

    await adjudicationService.setOverride(FILE, Q, KEY, 'printer')

    // `rationale ?? null` — an absent key and an explicit null are different to a JSON merge
    // patch, and clearing a rationale must actually clear it.
    expect(body).toEqual({ label: 'printer', rationale: null })
  })

  it('creates evidence with POST and edits it with PUT', async () => {
    const methods: string[] = []
    server.use(
      http.post('*/evidence', async ({ request }) => {
        methods.push(request.method)
        return HttpResponse.json({ id: 1 }, { status: 201 })
      }),
      http.put('*/evidence/*', async ({ request }) => {
        methods.push(request.method)
        return HttpResponse.json({ id: 1 })
      })
    )

    await adjudicationService.appendEvidence(FILE, Q, KEY, 'printer', 3, 'banner')
    await adjudicationService.updateEvidence(FILE, Q, KEY, 1, 'printer', 4, 'banner')

    // Append creates, edit replaces a known id — using POST for both would duplicate evidence
    // and re-weight the verdict every time an analyst corrected a typo.
    expect(methods).toEqual(['POST', 'PUT'])
  })

  it('carries the evidence weight and reason through unchanged', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/evidence', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 1 }, { status: 201 })
      })
    )

    await adjudicationService.appendEvidence(FILE, Q, KEY, 'printer', 3, 'HTTP banner')

    // Weight feeds the adjudicator's vote directly, so a dropped or coerced value changes the
    // verdict rather than just the display.
    expect(body).toEqual({ label: 'printer', weight: 3, reason: 'HTTP banner' })
  })

  it('propagates a 403 when editing evidence you do not own', async () => {
    let handled = false
    server.use(
      http.put('*/evidence/*', () => {
        handled = true
        return HttpResponse.json({ message: 'not yours' }, { status: 403 })
      })
    )

    // Author-only. Swallowing this would tell an analyst their correction was saved when the
    // backend refused it.
    await expect(
      adjudicationService.updateEvidence(FILE, Q, KEY, 1, 'printer', 4, 'x')
    ).rejects.toThrow()
    expect(handled).toBe(true)
  })

  it('resolves undefined when clearing an override returns 204', async () => {
    server.use(http.delete('*/adjudications/*', () => new HttpResponse(null, { status: 204 })))

    await expect(adjudicationService.clearOverride(FILE, Q, KEY)).resolves.toBeUndefined()
  })
})
