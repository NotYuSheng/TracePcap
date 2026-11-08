/**
 * The inactivity rule (#468, #488): when something missing from the latest capture stops being
 * "quiet" and becomes "no longer seen". One function for all three drift panels.
 */
import { describe, expect, it } from 'vitest'
import type { NetworkSnapshot } from '../../types/monitor.types'
import { DEFAULT_NETWORK_SETTINGS, describeRule, presenceOf } from '../presence'

function snap(id: string, order: number, startTime: string | null): NetworkSnapshot {
  return { id, snapshotOrder: order, startTime, fileId: `f-${id}`, fileName: `${id}.pcap` } as unknown as NetworkSnapshot
}

// Weekly captures: s1 (Oct 1) .. s4 (Oct 22, latest).
const weekly = [
  snap('s1', 0, '2026-10-01T09:00:00'),
  snap('s2', 1, '2026-10-08T09:00:00'),
  snap('s3', 2, '2026-10-15T09:00:00'),
  snap('s4', 3, '2026-10-22T09:00:00'),
]

describe('presenceOf', () => {
  it('defaults to today\'s behaviour: gone as soon as it misses the latest capture', () => {
    expect(presenceOf(weekly[2], weekly)).toBe('gone')
    expect(presenceOf(weekly[2], weekly, DEFAULT_NETWORK_SETTINGS)).toBe('gone')
  })

  it('by captures: quiet until missing from the last N captures', () => {
    const rule = { inactivityMode: 'SNAPSHOTS' as const, inactivityThreshold: 3 }
    expect(presenceOf(weekly[2], weekly, rule)).toBe('quiet') // missed 1 (s4)
    expect(presenceOf(weekly[1], weekly, rule)).toBe('quiet') // missed 2
    expect(presenceOf(weekly[0], weekly, rule)).toBe('gone') // missed 3
  })

  it('by days: quiet until more than N days before the latest capture', () => {
    const rule = { inactivityMode: 'DAYS' as const, inactivityThreshold: 14 }
    expect(presenceOf(weekly[2], weekly, rule)).toBe('quiet') // 7 days
    expect(presenceOf(weekly[1], weekly, rule)).toBe('quiet') // exactly 14 days
    expect(presenceOf(weekly[0], weekly, rule)).toBe('gone') // 21 days
  })

  it('by days, counts from the latest capture, not today, so old captures still work', () => {
    const old = [snap('a', 0, '2019-01-01T00:00:00'), snap('b', 1, '2019-01-03T00:00:00')]
    expect(presenceOf(old[0], old, { inactivityMode: 'DAYS', inactivityThreshold: 7 })).toBe('quiet')
  })

  it('by days, without capture times to compare, falls back to gone', () => {
    const untimed = [snap('a', 0, null), snap('b', 1, null)]
    expect(presenceOf(untimed[0], untimed, { inactivityMode: 'DAYS', inactivityThreshold: 30 })).toBe('gone')
  })
})

describe('describeRule', () => {
  it.each([
    [{ inactivityMode: 'SNAPSHOTS', inactivityThreshold: 1 }, 'as soon as it is missing from the latest capture'],
    [{ inactivityMode: 'SNAPSHOTS', inactivityThreshold: 3 }, 'missing from the last 3 captures'],
    [{ inactivityMode: 'DAYS', inactivityThreshold: 1 }, 'more than 1 day before'],
    [{ inactivityMode: 'DAYS', inactivityThreshold: 14 }, 'more than 14 days before'],
  ] as const)('%o reads "%s"', (rule, phrase) => {
    expect(describeRule(rule)).toContain(phrase)
  })
})
