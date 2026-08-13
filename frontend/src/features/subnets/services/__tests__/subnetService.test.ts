/**
 * The last untested service (#659). Subnet definitions decide how hosts are grouped and labelled
 * across every capture in a monitor network, and the `confirmed` flag is what separates an
 * analyst's judgement from a machine guess — which later drives staleness.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { subnetService } from '../subnetService'

const subnet = { id: 1, cidr: '10.0.0.0/8', label: 'Corp', confirmed: true }

/** Captures the body or query of whichever subnet endpoint is hit. */
function capture(method: 'post' | 'get' | 'delete', path: string, status = 200) {
  const seen: { body?: Record<string, unknown>; query?: URLSearchParams; calls: number } = {
    calls: 0,
  }
  const handler = async ({ request }: { request: Request }) => {
    seen.calls += 1
    seen.query = new URL(request.url).searchParams
    if (method === 'post') {
      seen.body = (await request.json().catch(() => ({}))) as Record<string, unknown>
    }
    return status === 200
      ? HttpResponse.json(subnet)
      : HttpResponse.json({ message: 'boom' }, { status })
  }
  server.use(http[method](path, handler))
  return seen
}

describe('subnetService', () => {
  it('lists subnet definitions', async () => {
    server.use(http.get('*/api/v1/subnets', () => HttpResponse.json([subnet])))

    await expect(subnetService.list()).resolves.toEqual([subnet])
  })

  it('carries the confirmed flag through an upsert', async () => {
    const seen = capture('post', '*/api/v1/subnets')

    await subnetService.upsert('10.0.0.0/8', 'Corp', 'head office', true, 'net-1')

    // `confirmed` is the analyst-versus-machine distinction, and networkId is what lets the
    // backend baseline staleness against that network's latest snapshot. Dropping either turns
    // a deliberate label into an unanchored guess.
    expect(seen.body).toEqual({
      cidr: '10.0.0.0/8',
      label: 'Corp',
      description: 'head office',
      confirmed: true,
      networkId: 'net-1',
    })
  })

  it('omits networkId when none is given rather than sending undefined', async () => {
    const seen = capture('post', '*/api/v1/subnets')

    await subnetService.upsert('10.0.0.0/8', 'Corp', '', false, undefined)

    expect(seen.body).toMatchObject({ confirmed: false })
    expect(seen.body?.networkId).toBeUndefined()
  })

  it('always saves a detected subnet as unconfirmed', async () => {
    const seen = capture('post', '*/api/v1/subnets/detected')

    await subnetService.saveDetected('10.0.0.0/8', 'Detected', 'auto')

    // Hard-coded, not a parameter. A machine-detected subnet must never arrive already
    // confirmed, or it would suppress the staleness prompts that ask a human to check it.
    expect(seen.body).toMatchObject({ confirmed: false })
  })

  it('passes the file id when detecting from a capture', async () => {
    const seen = capture('get', '*/api/v1/subnets/detect')

    await subnetService.detect('file-1')

    expect(seen.query?.get('fileId')).toBe('file-1')
  })

  it('detects from a network through its own endpoint', async () => {
    const seen = capture('get', '*/api/v1/subnets/detect/network')

    await subnetService.detectFromNetwork('net-1')

    // A separate route from the per-file detect: the network variant aggregates across
    // snapshots, so routing one to the other silently changes what is detected.
    expect(seen.query?.get('networkId')).toBe('net-1')
  })

  it('sends only the context it was given when suggesting a label', async () => {
    const seen = capture('post', '*/api/v1/subnets/*/suggest-label')

    await subnetService.suggestLabel(1, 'net-1')

    // The endpoint builds its query conditionally; an empty fileId= would be a filter for a
    // capture that does not exist.
    expect(seen.query?.get('networkId')).toBe('net-1')
    expect(seen.query?.has('fileId')).toBe(false)
  })

  it('surfaces a failed suggestion rather than resolving empty', async () => {
    const seen = capture('post', '*/api/v1/subnets/*/suggest-label', 500)

    await expect(subnetService.suggestLabel(1)).rejects.toThrow()
    expect(seen.calls).toBe(1)
  })

  it('reads composition history for a subnet within a network', async () => {
    const seen = capture('get', '*/api/v1/subnets/*/history')

    await subnetService.history(1, 'net-1')

    expect(seen.query?.get('networkId')).toBe('net-1')
  })

  it('deletes by id', async () => {
    let deletedPath: string | null = null
    server.use(
      http.delete('*/api/v1/subnets/:id', ({ request }) => {
        deletedPath = new URL(request.url).pathname
        return new HttpResponse(null, { status: 204 })
      })
    )

    await subnetService.delete(7)

    expect(deletedPath).toBe('/api/v1/subnets/7')
  })
})
