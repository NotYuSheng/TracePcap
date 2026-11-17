import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { aiJobsService } from '../aiJobsService'
import { useAiJob } from '../useAiJob'
import type { AiJob } from '../aiJobs.types'

vi.mock('../aiJobsService', () => ({
  AI_JOBS_CHANGED: 'tracepcap:ai-jobs-changed',
  aiJobsService: { list: vi.fn(), get: vi.fn(), cancel: vi.fn() },
}))
const svc = vi.mocked(aiJobsService)

const job = (over: Partial<AiJob> = {}): AiJob => ({
  id: 'j1',
  kind: 'STORY',
  subjectId: 'f1',
  subjectName: 'strrat.pcapng',
  trigger: 'USER',
  status: 'WAITING',
  position: 1,
  createdAt: '2026-11-17T10:00:00Z',
  ...over,
})

describe('following a background job', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    svc.list.mockResolvedValue([])
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('picks up a job already running for this capture, so a reload shows it', async () => {
    svc.list.mockResolvedValue([job({ status: 'RUNNING', startedAt: '2026-11-17T10:00:05Z' })])
    const { result } = renderHook(() => useAiJob('STORY', 'f1', {}))
    await waitFor(() => expect(result.current.active).toBe(true))
    expect(svc.list).toHaveBeenCalledWith({ kind: 'STORY', subjectId: 'f1' })
    expect(result.current.job?.status).toBe('RUNNING')
  })

  it('checks on it until it is done, then hands over the result', async () => {
    const onDone = vi.fn()
    const { result } = renderHook(() => useAiJob<string>('STORY', 'f1', { onDone }))
    svc.get.mockResolvedValueOnce(job({ status: 'RUNNING' })).mockResolvedValueOnce(job({ status: 'DONE', result: 'the story' }))

    await act(async () => {
      await result.current.start(async () => job())
    })
    expect(result.current.active).toBe(true)

    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(result.current.job?.status).toBe('RUNNING')
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })

    expect(onDone).toHaveBeenCalledWith('the story', expect.objectContaining({ status: 'DONE' }))
    expect(result.current.active).toBe(false)
    expect(svc.get).toHaveBeenCalledTimes(2)
  })

  it('reports a failure', async () => {
    const onFailed = vi.fn()
    const { result } = renderHook(() => useAiJob('STORY', 'f1', { onFailed }))
    svc.get.mockResolvedValueOnce(job({ status: 'FAILED', error: { errorCode: 'LLM_TIMEOUT', message: 'timed out' } }))
    await act(async () => { await result.current.start(async () => job()) })
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(onFailed).toHaveBeenCalledWith(expect.objectContaining({ status: 'FAILED' }))
  })

  it('stops following a job the backend no longer has', async () => {
    const { result } = renderHook(() => useAiJob('STORY', 'f1', {}))
    svc.get.mockRejectedValueOnce({ response: { status: 404 } })
    await act(async () => { await result.current.start(async () => job()) })
    await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
    expect(result.current.job).toBeNull()
  })

  it('cancels a waiting job', async () => {
    const { result } = renderHook(() => useAiJob('STORY', 'f1', {}))
    svc.cancel.mockResolvedValueOnce(job({ status: 'CANCELLED' }))
    await act(async () => { await result.current.start(async () => job()) })
    await act(async () => { await result.current.cancel() })
    expect(svc.cancel).toHaveBeenCalledWith('j1')
    expect(result.current.active).toBe(false)
  })
})
