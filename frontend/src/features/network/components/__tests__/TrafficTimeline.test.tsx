import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { GraphEdge } from '../../types'
import type { TimeWindow } from '../../services/timeWindow'
import { TrafficTimeline } from '../TrafficTimeline'

const edges = [0, 1, 2, 3].map(i => ({
  id: `c${i}`, source: 'a', target: 'b', label: '',
  data: { protocol: 'TCP', packetCount: 1, totalBytes: 100, conversationId: `c${i}`, bidirectional: true,
    startTime: 1_000_000 + i * 600_000, endTime: 1_000_000 + i * 600_000 + 1000 },
})) as GraphEdge[]
const bounds = { from: 1_000_000, to: 1_000_000 + 3 * 600_000 + 1000 }

function Harness({ onChange }: { onChange?: (w: TimeWindow | null) => void }) {
  const [w, setW] = useState<TimeWindow | null>(null)
  return (
    <TrafficTimeline
      edges={edges}
      bounds={bounds}
      window={w}
      onWindowChange={x => { setW(x); onChange?.(x) }}
      activeCount={w ? 1 : edges.length}
    />
  )
}

describe('TrafficTimeline', () => {
  it('starts on the whole capture, and Show all returns to it', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    expect(screen.getByTestId('timeline-readout')).toHaveTextContent('Whole capture')
    expect(screen.getByRole('button', { name: 'Show all' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('From'), { target: { value: String(bounds.from + 700_000) } })
    expect(screen.getByTestId('timeline-readout')).toHaveTextContent('1 of 4 conversations')
    await user.click(screen.getByRole('button', { name: 'Show all' }))
    expect(screen.getByTestId('timeline-readout')).toHaveTextContent('Whole capture')
  })

  it('plays a window through the capture and stops at the end', () => {
    vi.useFakeTimers()
    const seen: (TimeWindow | null)[] = []
    render(<Harness onChange={w => seen.push(w)} />)
    act(() => { fireEvent.click(screen.getByRole('button', { name: 'Play through the capture' })) })
    expect(seen[0]).toEqual({ from: bounds.from, to: bounds.from + (bounds.to - bounds.from) * 0.1 })
    act(() => { vi.advanceTimersByTime(40_000) })
    const last = seen[seen.length - 1]!
    expect(last.to).toBe(bounds.to)
    expect(screen.getByRole('button', { name: 'Play through the capture' })).toBeInTheDocument() // stopped
    vi.useRealTimers()
  })
})
