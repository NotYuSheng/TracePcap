import { describe, expect, it } from 'vitest'

import { extendedTo, MAX_KEEP_MS, ownExpiry } from '../captureKeepService'

const DAY = 24 * 3600_000
const NOW = Date.UTC(2026, 10, 15, 12, 0)

describe('extendedTo', () => {
  it('adds the days to when it would be deleted, so extending twice adds up', () => {
    expect(extendedTo(NOW + 2 * DAY, 7, NOW)).toBe(NOW + 9 * DAY)
  })

  it('counts from now when the deletion time has passed or there is none', () => {
    expect(extendedTo(NOW - DAY, 1, NOW)).toBe(NOW + DAY)
    expect(extendedTo(null, 1, NOW)).toBe(NOW + DAY)
  })

  it('never asks for more than the backend allows', () => {
    expect(extendedTo(NOW + 360 * DAY, 30, NOW)).toBeLessThan(NOW + MAX_KEEP_MS)
  })
})

describe('ownExpiry', () => {
  it('reads the API date array, a number, or none', () => {
    expect(ownExpiry([2026, 12, 15, 18, 0])).toBe(new Date(2026, 11, 15, 18, 0).getTime())
    expect(ownExpiry(NOW)).toBe(NOW)
    expect(ownExpiry(null)).toBeNull()
  })
})
