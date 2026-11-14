import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { GraphEdge } from '../../types'
import type { TimeWindow } from '../../services/timeWindow'
import { TimeScrubber } from '../TimeScrubber'

const edges = [0, 1, 2, 3].map(i => ({
  id: `c${i}`, source: 'a', target: 'b', label: '',
  data: { protocol: 'TCP', packetCount: 1, totalBytes: 100, conversationId: `c${i}`, bidirectional: true,
    startTime: 1_000_000 + i * 600_000, endTime: 1_000_000 + i * 600_000 + 1000 },
})) as GraphEdge[]
const bounds = { from: 1_000_000, to: 1_000_000 + 3 * 600_000 + 1000 }

function Harness({ onChange }: { onChange?: (w: TimeWindow | null) => void }) {
  const [w, setW] = useState<TimeWindow | null>(null)
  const [appear, setAppear] = useState(false)
  const [unseen, setUnseen] = useState<'hide' | 'faint'>('hide')
  return (
    <TimeScrubber
      edges={edges}
      bounds={bounds}
      window={w}
      onWindowChange={x => { setW(x); onChange?.(x) }}
      activeCount={w ? 1 : edges.length}
      animate={false}
      onAnimateChange={() => {}}
      appearWhenSeen={appear}
      onAppearWhenSeenChange={setAppear}
      unseenStyle={unseen}
      onUnseenStyleChange={setUnseen}
    />
  )
}

describe('TimeScrubber', () => {
  it('starts on the whole capture; the keyboard moves a window; × goes back to the whole capture', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    expect(screen.getByTestId('timeline-readout')).toHaveTextContent('Whole capture')
    expect(screen.queryByRole('button', { name: 'Show the whole capture' })).not.toBeInTheDocument()
    const slider = screen.getByRole('slider', { name: 'Time window' })
    slider.focus()
    await user.keyboard('{End}')
    expect(screen.getByTestId('timeline-readout')).toHaveTextContent('1 of 4 conversations')
    await user.click(screen.getByRole('button', { name: 'Show the whole capture' }))
    expect(screen.getByTestId('timeline-readout')).toHaveTextContent('Whole capture')
  })

  it('Escape on the slider shows the whole capture again', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const slider = screen.getByRole('slider', { name: 'Time window' })
    slider.focus()
    await user.keyboard('{ArrowRight}')
    expect(slider).toHaveAttribute('aria-valuetext', expect.stringContaining(' to '))
    await user.keyboard('{Escape}')
    expect(slider).toHaveAttribute('aria-valuetext', 'The whole capture')
  })

  it('plays a window through the capture and stops at the end', () => {
    vi.useFakeTimers()
    const seen: (TimeWindow | null)[] = []
    render(<Harness onChange={w => seen.push(w)} />)
    act(() => { fireEvent.click(screen.getByRole('button', { name: 'Play through the capture' })) })
    expect(seen[0]).toEqual({ from: bounds.from, to: bounds.from + (bounds.to - bounds.from) * 0.1 })
    act(() => { vi.advanceTimersByTime(40_000) })
    expect(seen[seen.length - 1]!.to).toBe(bounds.to)
    expect(screen.getByRole('button', { name: 'Play through the capture' })).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('settings hold the window width, speed, animation and the appear-when-seen option', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    await user.click(screen.getByRole('button', { name: 'Time axis settings' }))
    await user.click(await screen.findByRole('button', { name: '25%' }))
    expect(screen.getByRole('button', { name: '25%' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('timeline-readout')).not.toHaveTextContent('Whole capture')
    const appear = screen.getByRole('switch', { name: 'Nodes appear when first seen' })
    expect(appear).not.toBeChecked()
    expect(screen.queryByRole('button', { name: 'Show them faint' })).not.toBeInTheDocument()
    await user.click(appear)
    expect(appear).toBeChecked()
    // Not-seen nodes: hidden by default, or faint.
    expect(screen.getByRole('button', { name: 'Hide them' })).toHaveAttribute('aria-pressed', 'true')
    await user.click(screen.getByRole('button', { name: 'Show them faint' }))
    expect(screen.getByRole('button', { name: 'Show them faint' })).toHaveAttribute('aria-pressed', 'true')
  })
})
