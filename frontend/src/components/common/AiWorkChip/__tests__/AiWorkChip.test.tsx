import { act, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { aiJobsService } from '@/features/aiJobs/aiJobsService'
import type { AiJob } from '@/features/aiJobs/aiJobs.types'
import { AiWorkChip } from '../AiWorkChip'

vi.mock('@/features/aiJobs/aiJobsService', () => ({
  AI_JOBS_CHANGED: 'tracepcap:ai-jobs-changed',
  aiJobsService: { list: vi.fn() },
}))
const svc = vi.mocked(aiJobsService)

const story: AiJob = {
  id: 's1', kind: 'STORY', subjectId: 'f1', subjectName: 'strrat-you-dirty-rat.pcapng', trigger: 'USER',
  status: 'RUNNING', createdAt: '2026-11-17T10:00:00Z', startedAt: '2026-11-17T10:00:01Z', typicalMs: 420_000,
}
const insights: AiJob = {
  id: 'i1', kind: 'INSIGHTS', subjectId: 'n1', subjectName: 'Office Audit — Corp HQ', trigger: 'USER',
  status: 'WAITING', position: 1, createdAt: '2026-11-17T10:01:00Z',
}

const show = (path = '/') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <AiWorkChip />
    </MemoryRouter>
  )

describe('the header AI work chip', () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }))
  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('is not there while the model has nothing to do', async () => {
    svc.list.mockResolvedValue([])
    show()
    await act(async () => {})
    expect(screen.queryByTestId('ai-work-chip')).toBeNull()
  })

  it('says what is running and waiting, and lists where each lands', async () => {
    svc.list.mockResolvedValue([story, insights])
    show()
    const chip = await screen.findByTestId('ai-work-chip')
    expect(chip).toHaveTextContent('AI · 1 running · 1 waiting')

    fireEvent.click(chip)
    expect(await screen.findByText('strrat-you-dirty-rat.pcapng', { exact: false })).toBeInTheDocument()
    expect(screen.getByText(/Waiting · next in line/)).toBeInTheDocument()
    const links = screen.getAllByRole('link', { name: 'Open' })
    expect(links.map(a => a.getAttribute('href'))).toEqual(['/analysis/f1/story', '/monitor/n1'])
  })

  it('notes a job it saw running once it finishes', async () => {
    svc.list.mockResolvedValueOnce([insights]).mockResolvedValue([{ ...insights, status: 'DONE', position: null }])
    show('/analysis/f1/story')
    await screen.findByTestId('ai-work-chip')

    await act(async () => { await vi.advanceTimersByTimeAsync(4000) })

    expect(await screen.findByText('Insights ready')).toBeInTheDocument()
    expect(screen.queryByTestId('ai-work-chip')).toBeNull()
  })

  it("doesn't note it when you're already on the page it lands on", async () => {
    svc.list.mockResolvedValueOnce([insights]).mockResolvedValue([{ ...insights, status: 'DONE', position: null }])
    show('/monitor/n1')
    await screen.findByTestId('ai-work-chip')
    await act(async () => { await vi.advanceTimersByTimeAsync(4000) })
    expect(screen.queryByText('Insights ready')).toBeNull()
  })
})
