/**
 * The conversation flow header shows an identity chip for each of its two endpoints. It must ask
 * for just those two hosts, not every host in the file (#576). The IPs go as one comma-separated
 * `ips` param: axios's default array form (`ips[]=a&ips[]=b`) doesn't bind to Spring's List<String>.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { conversationService } from '../conversationService'

const FILE = '11111111-1111-1111-1111-111111111111'

function capture() {
  const seen: { query?: URLSearchParams } = {}
  server.use(
    http.get('*/api/v1/files/:fileId/host-identities', ({ request }) => {
      seen.query = new URL(request.url).searchParams
      return HttpResponse.json([{ ip: '10.0.0.1', primaryLabel: 'ROUTER', contested: false }])
    })
  )
  return seen
}

describe('conversationService.getHostIdentities', () => {
  it('scopes to the given IPs as one comma-separated param', async () => {
    const seen = capture()

    const result = await conversationService.getHostIdentities(FILE, ['10.0.0.1', 'fe80::1'])

    expect(seen.query?.get('ips')).toBe('10.0.0.1,fe80::1')
    expect(seen.query?.has('ips[]')).toBe(false)
    expect(result.map(i => i.ip)).toEqual(['10.0.0.1'])
  })

  it('omits the param entirely when no IPs are given (every host)', async () => {
    const seen = capture()

    await conversationService.getHostIdentities(FILE)

    expect(seen.query?.has('ips')).toBe(false)
  })
})
