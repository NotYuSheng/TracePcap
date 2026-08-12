/**
 * Subnet definitions are the operator's map of their own network: which ranges are which.
 * `confirmed` is the flag separating "the tool guessed this" from "a human said so", and it
 * drives the staleness workflow, so a write that sets it wrongly launders a guess into a fact.
 */
import { HttpResponse, http } from 'msw'
import { describe, expect, it } from 'vitest'

import { server } from '@/test/msw'
import { subnetService } from '../subnetService'

/** Captures the JSON body posted to a subnet endpoint. */
function capturePost(path: string) {
  const seen: { body?: Record<string, unknown>; handled: boolean } = { handled: false }
  server.use(
    http.post(path, async ({ request }) => {
      seen.handled = true
      seen.body = (await request.json()) as Record<string, unknown>
      return HttpResponse.json({ id: 1, cidr: '10.0.0.0/8', label: 'Corp' }, { status: 201 })
    })
  )
  return seen
}

describe('subnetService', () => {
  it('sends the confirmed flag the caller chose', async () => {
    const seen = capturePost('*/api/v1/subnets')

    await subnetService.upsert('10.0.0.0/8', 'Corp', 'HQ range', true)

    expect(seen.body).toMatchObject({
      cidr: '10.0.0.0/8',
      label: 'Corp',
      description: 'HQ range',
      confirmed: true,
    })
  })

  it('omits networkId entirely when not supplied', async () => {
    const seen = capturePost('*/api/v1/subnets')

    await subnetService.upsert('10.0.0.0/8', 'Corp', '', false)

    // The key is in the object literal but undefined, and JSON.stringify drops it. Sending an
    // explicit null instead would clear the staleness baseline the backend captures from it.
    expect(seen.body).not.toHaveProperty('networkId')
  })

  it('passes networkId through when supplied', async () => {
    const seen = capturePost('*/api/v1/subnets')

    await subnetService.upsert('10.0.0.0/8', 'Corp', '', true, 'net-1')

    // Only present on a confirm, where it tells the backend which snapshot to baseline against.
    expect(seen.body).toMatchObject({ networkId: 'net-1' })
  })

  it('always saves a detected subnet as unconfirmed', async () => {
    const seen = capturePost('*/api/v1/subnets/detected')

    await subnetService.saveDetected('192.168.0.0/16', 'Guessed', 'from traffic')

    // Hard-coded, and must stay so: a detected range is the tool's guess. Marking it confirmed
    // would launder that guess into something the UI presents as operator-verified.
    expect(seen.body).toMatchObject({ confirmed: false })
  })

  it('surfaces a rejected subnet rather than reporting success', async () => {
    let handled = false
    server.use(
      http.post('*/api/v1/subnets', () => {
        handled = true
        return HttpResponse.json({ message: 'overlaps an existing range' }, { status: 400 })
      })
    )

    await expect(subnetService.upsert('10.0.0.0/8', 'Corp', '', true)).rejects.toThrow()
    // Asserts the rejection came from the endpoint, not from an unmatched URL.
    expect(handled, 'the subnets endpoint was never reached').toBe(true)
  })

  it('lists and deletes against the versioned paths', async () => {
    let deleted: string | null = null
    server.use(
      http.get('*/api/v1/subnets', () =>
        HttpResponse.json([{ id: 1, cidr: '10.0.0.0/8', label: 'Corp' }])
      ),
      http.delete('*/api/v1/subnets/:id', ({ request }) => {
        deleted = new URL(request.url).pathname
        return new HttpResponse(null, { status: 204 })
      })
    )

    await expect(subnetService.list()).resolves.toHaveLength(1)
    await subnetService.delete(4)
    expect(deleted).toBe('/api/v1/subnets/4')
  })
})
