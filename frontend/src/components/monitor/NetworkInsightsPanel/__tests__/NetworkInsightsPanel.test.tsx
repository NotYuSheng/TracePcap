import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { AiJob } from '@/features/aiJobs/aiJobs.types'
import { NetworkInsightsPanel } from '../NetworkInsightsPanel'

const job = (over: Partial<AiJob>): AiJob => ({
  id: 'i1', kind: 'INSIGHTS', subjectId: 'n1', subjectName: 'Office Audit — Corp HQ', trigger: 'USER',
  status: 'WAITING', position: 2, createdAt: '2026-11-17T10:01:00Z', ...over,
})

describe('insights generated in the background', () => {
  it('shows a waiting job in place, with its place in line and Cancel', () => {
    const onCancelJob = vi.fn().mockResolvedValue(undefined)
    render(<NetworkInsightsPanel insight={null} llmAvailable onGenerate={vi.fn()} job={job({})} onCancelJob={onCancelJob} />)

    expect(screen.getByText('Waiting for the model')).toBeInTheDocument()
    expect(screen.getByText(/2nd in line/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Queued/ })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onCancelJob).toHaveBeenCalled()
  })

  it('shows a running job without Cancel: the model is already answering', () => {
    render(
      <NetworkInsightsPanel
        insight={null}
        llmAvailable
        onGenerate={vi.fn()}
        job={job({ status: 'RUNNING', position: null, startedAt: new Date().toISOString(), typicalMs: 120_000 })}
        onCancelJob={vi.fn()}
      />
    )
    expect(screen.getByText('Generating insights in the background')).toBeInTheDocument()
    expect(screen.getByText(/usually about 2 min/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull()
  })

  it('works as before without a job', () => {
    render(<NetworkInsightsPanel insight={null} llmAvailable onGenerate={vi.fn()} />)
    expect(screen.getByText('No insights generated yet.')).toBeInTheDocument()
    expect(screen.queryByTestId('ai-job-status')).toBeNull()
  })
})
