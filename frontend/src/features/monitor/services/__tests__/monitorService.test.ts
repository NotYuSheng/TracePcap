/**
 * Monitor networks group snapshots over time, so these writes shape what change detection
 * later compares against. A snapshot added with the wrong subnet overrides re-baselines the
 * whole network silently.
 *
 * These also assert the HTTP *method*, which nothing else in the suite does. #659 deprioritised
 * a regex scanner for method/path pairs because it could only see a quarter of call sites — but
 * where a service is tested directly, the method is free to pin, and `updateNetwork` using PATCH
 * rather than PUT is a real convention from CLAUDE.md.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { monitorService } from '../monitorService'

const NET = 'net-1'
const network = { id: NET, name: 'HQ', description: 'head office' }

describe('monitorService', () => {
  it('creates a network with name and description', async () => {
    let body: unknown = null
    server.use(
      http.post('*/api/v1/monitor/networks', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json(network, { status: 201 })
      })
    )

    await expect(monitorService.createNetwork('HQ', 'head office')).resolves.toEqual(network)
    expect(body).toEqual({ name: 'HQ', description: 'head office' })
  })

  it('updates via PATCH, not PUT', async () => {
    let patched = false
    server.use(
      http.patch('*/api/v1/monitor/networks/:id', () => {
        patched = true
        return HttpResponse.json(network)
      }),
      // If the service ever switched to PUT this handler would take the request instead, and
      // the assertion below would catch it rather than the call simply failing.
      http.put('*/api/v1/monitor/networks/:id', () => HttpResponse.json(network))
    )

    await monitorService.updateNetwork(NET, 'HQ', 'head office')

    expect(patched, 'updateNetwork did not use PATCH').toBe(true)
  })

  it('resolves undefined when a delete returns 204 with no body', async () => {
    server.use(
      http.delete('*/api/v1/monitor/networks/:id', () => new HttpResponse(null, { status: 204 }))
    )

    // `.then(() => undefined)` — the caller awaits it, so a body-parsing attempt here would
    // reject on an empty response.
    await expect(monitorService.deleteNetwork(NET)).resolves.toBeUndefined()
  })

  it('omits subnetOverrides when none are supplied', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/api/v1/monitor/networks/:id/snapshots', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 's1' }, { status: 201 })
      })
    )

    await monitorService.addSnapshot(NET, 'file-1')

    // Conditionally spread, so the key is absent rather than an empty array. The backend treats
    // absent as "use the network's existing subnet definitions"; an empty array would mean
    // "override with nothing" and re-baseline the snapshot.
    expect(body).toEqual({ fileId: 'file-1' })
  })

  it('omits subnetOverrides when the array is empty', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/api/v1/monitor/networks/:id/snapshots', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 's1' }, { status: 201 })
      })
    )

    await monitorService.addSnapshot(NET, 'file-1', [])

    expect(body).not.toHaveProperty('subnetOverrides')
  })

  it('includes subnetOverrides when supplied', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.post('*/api/v1/monitor/networks/:id/snapshots', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 's1' }, { status: 201 })
      })
    )

    await monitorService.addSnapshot(NET, 'file-1', [
      { cidr: '10.0.0.0/8', label: 'Corp' } as never,
    ])

    expect(body).toMatchObject({ subnetOverrides: [{ cidr: '10.0.0.0/8', label: 'Corp' }] })
  })
})
