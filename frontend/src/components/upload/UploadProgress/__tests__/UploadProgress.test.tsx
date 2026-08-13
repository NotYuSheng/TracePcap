/**
 * The upload card. Its job is to distinguish four states that a user experiences very
 * differently — uploading, processing, done, failed — and the awkward one is "processing": the
 * bytes are transferred but the server is still working, so a naive reading of progress===100
 * would announce success while analysis is still running.
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { UploadProgress } from '../UploadProgress'

function renderCard(props: Partial<Parameters<typeof UploadProgress>[0]> = {}) {
  const onAnalyze = vi.fn()
  const onOpenExisting = vi.fn()
  render(
    <UploadProgress
      fileName="capture.pcap"
      progress={0}
      isUploading
      onAnalyze={onAnalyze}
      onOpenExisting={onOpenExisting}
      {...props}
    />
  )
  return { onAnalyze, onOpenExisting }
}

const bar = () => screen.getByRole('progressbar')

describe('UploadProgress', () => {
  it('counts up while bytes are still going', () => {
    renderCard({ progress: 42, isUploading: true })

    expect(screen.getByText('Uploading 42%')).toBeInTheDocument()
    expect(bar()).toHaveAttribute('aria-valuenow', '42')
  })

  it('says Processing when the bytes are in but the server is still working', () => {
    renderCard({ progress: 100, isUploading: true })

    // The distinction that matters. Announcing "Complete" here sends the user to look for an
    // analysis that does not exist yet.
    expect(screen.getByText('Processing…')).toBeInTheDocument()
    expect(screen.queryByText('Complete')).not.toBeInTheDocument()
  })

  it('announces completion only once the server is done', () => {
    renderCard({ progress: 100, isUploading: false })

    expect(screen.getByText('Complete')).toBeInTheDocument()
  })

  it('reports a failure instead of a percentage', () => {
    renderCard({ progress: 60, isUploading: false, error: 'Not a valid pcap' })

    // The status line and the reason are separate: one says what happened, the other why.
    expect(screen.getByText('Upload failed')).toBeInTheDocument()
    expect(screen.getByText('Not a valid pcap')).toBeInTheDocument()
  })

  it('prefers the error over any progress state', () => {
    renderCard({ progress: 100, isUploading: false, error: 'Storage error' })

    // A failure at 100% must not read as Complete — this is the combination most likely to be
    // rendered wrong, because both conditions are satisfied.
    expect(screen.getByText('Upload failed')).toBeInTheDocument()
    expect(screen.queryByText('Complete')).not.toBeInTheDocument()
  })

  it('offers Analyze only when the upload has finished', async () => {
    const { onAnalyze } = renderCard({ progress: 100, isUploading: false })

    await userEvent.click(screen.getByRole('button', { name: /Analyze/ }))

    expect(onAnalyze).toHaveBeenCalled()
  })

  it('does not offer Analyze mid-upload', () => {
    renderCard({ progress: 80, isUploading: true })

    // Analysing a partially uploaded capture would read a truncated file.
    expect(screen.queryByRole('button', { name: /Analyze/ })).not.toBeInTheDocument()
  })

  it('explains what to do about a duplicate rather than just flagging it', async () => {
    const { onOpenExisting } = renderCard({
      progress: 100,
      isUploading: false,
      isDuplicate: true,
    })

    // A duplicate is not an error, so the card offers the existing analysis and says how to
    // reprocess — an unexplained warning leaves the user stuck.
    expect(screen.getByText(/already been uploaded/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Open existing/ }))
    expect(onOpenExisting).toHaveBeenCalled()
  })

  it('does not flag a duplicate while the upload is still in flight', () => {
    renderCard({ progress: 100, isUploading: true, isDuplicate: true })

    // The duplicate verdict comes from the server's response; showing it during processing
    // would pre-empt a result that has not arrived.
    expect(screen.queryByText(/already been uploaded/)).not.toBeInTheDocument()
  })

  it('names the file its progress belongs to (#723)', () => {
    renderCard({ fileName: 'evidence.pcap', progress: 40 })

    // Without a name a screen reader announces a bare percentage; with several uploads in
    // flight the announcements are indistinguishable.
    expect(screen.getByRole('progressbar', { name: /evidence\.pcap/ })).toBeInTheDocument()
  })

  it('fills the bar during processing even though progress is indeterminate', () => {
    renderCard({ progress: 100, isUploading: true })

    expect(bar()).toHaveStyle({ width: '100%' })
    expect(bar()).toHaveClass('progress-bar-animated')
  })
})
