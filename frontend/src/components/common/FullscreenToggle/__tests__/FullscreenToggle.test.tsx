import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { FullscreenToggle } from '../FullscreenToggle'

describe('FullscreenToggle', () => {
  it('shows no hint until signalled', () => {
    render(<FullscreenToggle isFullscreen={false} onToggle={() => {}} />)
    expect(screen.queryByText(/Looking for fullscreen/)).not.toBeInTheDocument()
  })

  it('points itself out when signalled; Escape dismisses the hint', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<FullscreenToggle isFullscreen={false} onToggle={() => {}} hintSignal={0} />)
    rerender(<FullscreenToggle isFullscreen={false} onToggle={() => {}} hintSignal={1} />)
    expect(await screen.findByText(/Looking for fullscreen/)).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByText(/Looking for fullscreen/)).not.toBeInTheDocument()
  })

  it('in fullscreen, says how to leave it; clicking toggles and hides the hint', async () => {
    const user = userEvent.setup()
    const onToggle = vi.fn()
    render(<FullscreenToggle isFullscreen onToggle={onToggle} hintSignal={1} />)
    expect(await screen.findByText(/To leave fullscreen/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Exit fullscreen' }))
    expect(onToggle).toHaveBeenCalledOnce()
    expect(screen.queryByText(/To leave fullscreen/)).not.toBeInTheDocument()
  })
})
