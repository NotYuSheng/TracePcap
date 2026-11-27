/**
 * IP-org rules label ranges of addresses in every view that renders an IP. The CIDR an operator
 * types is checked and written by the backend's Cidr.normalise (#1351): this client used to keep
 * its own looser copy (it sent ":/128" and "10.0.1.0/24junk"), a second definition of the rule.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { ipOrgRuleService } from '../ipOrgRuleService'

describe('ipOrgRuleService', () => {
  it('sends what the operator typed, trimmed, and leaves the CIDR rule to the backend', async () => {
    const seen: { body?: Record<string, unknown> } = {}
    server.use(
      http.post('*/api/v1/ip-org-rules', async ({ request }) => {
        seen.body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 1, label: 'Corp', cidr: '8.8.8.8/32' }, { status: 201 })
      })
    )
    const saved = await ipOrgRuleService.create('Corp', '  8.8.8.8  ')
    expect(seen.body).toEqual({ label: 'Corp', cidr: '8.8.8.8' })
    expect(saved.cidr).toBe('8.8.8.8/32') // the backend's answer, as stored
  })

  it("surfaces the backend's refusal of a bad CIDR", async () => {
    server.use(
      http.post('*/api/v1/ip-org-rules', () => HttpResponse.text('Invalid CIDR: nonsense', { status: 400 }))
    )
    await expect(ipOrgRuleService.create('Corp', 'nonsense')).rejects.toThrow()
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
