import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { useEscapeLayerRoot } from '@utils/useEscapeLayer'
import { FullscreenToggle } from '../FullscreenToggle'

function Root({ children }: { children: React.ReactNode }) {
  useEscapeLayerRoot()
  return <>{children}</>
}

describe('FullscreenToggle', () => {
  it('shows no hint until signalled', () => {
    render(<FullscreenToggle isFullscreen={false} onToggle={() => {}} />)
    expect(screen.queryByText(/Looking for fullscreen/)).not.toBeInTheDocument()
  })

  it('points itself out when signalled; Escape dismisses the hint', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<Root><FullscreenToggle isFullscreen={false} onToggle={() => {}} hintSignal={0} /></Root>)
    rerender(<Root><FullscreenToggle isFullscreen={false} onToggle={() => {}} hintSignal={1} /></Root>)
    expect(await screen.findByText(/Looking for fullscreen/)).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByText(/Looking for fullscreen/)).not.toBeInTheDocument())
  })

  it('in fullscreen, says how to leave it; clicking toggles and hides the hint', async () => {
    const user = userEvent.setup()
    const onToggle = vi.fn()
    render(<FullscreenToggle isFullscreen onToggle={onToggle} hintSignal={1} />)
    expect(await screen.findByText(/To leave fullscreen/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Exit fullscreen' }))
    expect(onToggle).toHaveBeenCalledOnce()
    await waitFor(() => expect(screen.queryByText(/To leave fullscreen/)).not.toBeInTheDocument())
  })

  it('survives the click that raised it (a Fit view press elsewhere on the page)', async () => {
    const user = userEvent.setup()
    function Page() {
      const [n, setN] = useState(0)
      return (
        <Root>
          <FullscreenToggle isFullscreen={false} onToggle={() => {}} hintSignal={n} />
          <button type="button" onClick={() => setN(x => x + 1)}>Fit view</button>
        </Root>
      )
    }
    render(<Page />)
    await user.click(screen.getByRole('button', { name: 'Fit view' }))
    expect(await screen.findByText(/Looking for fullscreen/)).toBeInTheDocument()
    await new Promise(r => setTimeout(r, 50))
    expect(screen.getByText(/Looking for fullscreen/)).toBeInTheDocument()
  })
})
