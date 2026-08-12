/**
 * IP-org rules label ranges of addresses in every view that renders an IP, so a rule stored
 * against the wrong range mislabels traffic everywhere at once.
 *
 * The normalisation runs entirely client-side before the request, which makes it the only
 * validation between an operator's typing and the database. These pin what it accepts —
 * including where it is looser than it looks.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { ipOrgRuleService } from '../ipOrgRuleService'

/** Captures the body sent to the create endpoint. */
function captureCreate() {
  const seen: { body?: Record<string, unknown> } = {}
  server.use(
    http.post('*/api/v1/ip-org-rules', async ({ request }) => {
      seen.body = (await request.json()) as Record<string, unknown>
      return HttpResponse.json({ id: 1, label: 'x', cidr: 'x' }, { status: 201 })
    })
  )
  return seen
}

async function sentCidr(input: string): Promise<unknown> {
  const seen = captureCreate()
  await ipOrgRuleService.create('Corp', input)
  return seen.body!.cidr
}

describe('ipOrgRuleService normalisation', () => {
  it('widens a bare IPv4 address to a /32', async () => {
    // An operator typing a single address means "just this host".
    await expect(sentCidr('8.8.8.8')).resolves.toBe('8.8.8.8/32')
  })

  it('widens a bare IPv6 address to a /128', async () => {
    await expect(sentCidr('2001:db8::1')).resolves.toBe('2001:db8::1/128')
  })

  it('passes an already-valid CIDR through untouched', async () => {
    await expect(sentCidr('10.0.1.0/24')).resolves.toBe('10.0.1.0/24')
  })

  it('trims surrounding whitespace before deciding', async () => {
    await expect(sentCidr('  10.0.1.0/24  ')).resolves.toBe('10.0.1.0/24')
  })

  it.each([
    ['10.0.0.256/24', 'octet above 255'],
    ['10.0.0.0/33', 'IPv4 prefix above 32'],
    ['not-an-ip', 'no dots or colons'],
    ['10.0.0.0/x', 'non-numeric prefix'],
  ])('rejects %s (%s)', async input => {
    // A handler must be registered and asserted unreached. Without one, MSW errors on the
    // unhandled request and `rejects.toThrow()` passes for that reason instead — which made an
    // earlier version of this test pass even with the prefix bound deleted.
    let handled = false
    server.use(
      http.post('*/api/v1/ip-org-rules', () => {
        handled = true
        return HttpResponse.json({}, { status: 201 })
      })
    )

    await expect(ipOrgRuleService.create('Corp', input)).rejects.toThrow()
    expect(handled, `"${input}" was sent to the backend instead of being rejected`).toBe(false)
  })

  it('rejects before sending anything, so a bad rule cannot reach the backend', async () => {
    let handled = false
    server.use(
      http.post('*/api/v1/ip-org-rules', () => {
        handled = true
        return HttpResponse.json({}, { status: 201 })
      })
    )

    await expect(ipOrgRuleService.create('Corp', 'nonsense')).rejects.toThrow()
    // The validation is client-side only, so this is what guarantees the backend never sees it.
    expect(handled, 'a rejected rule still reached the network').toBe(false)
  })

  describe('known looseness — pinned, not endorsed', () => {
    it('accepts a bare colon as IPv6 and widens it to /128', async () => {
      // The IPv6 branch is `s.includes(':')` with no further validation, so ":" normalises to
      // ":/128" and is stored. The backend is the only thing that would reject it.
      await expect(sentCidr(':')).resolves.toBe(':/128')
    })

    it('accepts trailing junk on a prefix because parseInt stops at the first non-digit', async () => {
      // parseInt("24junk") is 24, so this passes validation and is stored verbatim — prefix
      // and junk together.
      await expect(sentCidr('10.0.1.0/24junk')).resolves.toBe('10.0.1.0/24junk')
    })
  })

  it('lists and deletes through the endpoint map', async () => {
    let deletedPath: string | null = null
    server.use(
      http.get('*/api/v1/ip-org-rules', () =>
        HttpResponse.json([{ id: 1, label: 'Corp', cidr: '10.0.0.0/8' }])
      ),
      http.delete('*/api/v1/ip-org-rules/:id', ({ request }) => {
        deletedPath = new URL(request.url).pathname
        return new HttpResponse(null, { status: 204 })
      })
    )

    await expect(ipOrgRuleService.list()).resolves.toHaveLength(1)
    await ipOrgRuleService.delete(9)
    expect(deletedPath).toBe('/api/v1/ip-org-rules/9')
  })
})
