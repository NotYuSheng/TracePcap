import { describe, expect, it } from 'vitest'
import { jobPath, placeInLine, runningFor, shortDuration } from '../aiJobText'
import type { AiJob } from '../aiJobs.types'

describe('how a background job is described', () => {
  it('says where a waiting job is in line', () => {
    expect(placeInLine(1)).toBe('next in line')
    expect(placeInLine(2)).toBe('2nd in line')
    expect(placeInLine(3)).toBe('3rd in line')
    expect(placeInLine(4)).toBe('4th in line')
    expect(placeInLine(11)).toBe('11th in line')
    expect(placeInLine(22)).toBe('22nd in line')
  })

  it('rounds durations to what a person reads', () => {
    expect(shortDuration(18_000)).toBe('18 s')
    expect(shortDuration(415_000)).toBe('7 min')
    expect(shortDuration(3_900_000)).toBe('1 h 5 min')
  })

  it('counts running time from when it started, not when it was asked for', () => {
    const job = { startedAt: '2026-11-17T10:00:00Z' } as AiJob
    expect(runningFor(job, Date.parse('2026-11-17T10:03:00Z'))).toBe(180_000)
    expect(runningFor({ startedAt: null } as AiJob, Date.now())).toBe(0)
  })

  it('links each kind to where its answer lands', () => {
    expect(jobPath({ kind: 'STORY', subjectId: 'f1' } as AiJob)).toBe('/analysis/f1/story')
    expect(jobPath({ kind: 'INSIGHTS', subjectId: 'n1' } as AiJob)).toBe('/monitor/n1')
    expect(jobPath({ kind: 'ROLE_PREVIEW', subjectId: 'f1' } as AiJob)).toBe('/analysis/f1/network-diagram')
    expect(jobPath({ kind: 'SUBNET_LABEL', subjectId: null } as AiJob)).toBeNull()
    expect(jobPath({ kind: 'TRACE_EXPLANATIONS', subjectId: null } as AiJob)).toBeNull()
  })
})
