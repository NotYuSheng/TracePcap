import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { GraphEdge } from '../../types'
import type { PacketReplay } from '../../hooks/usePacketReplay'
import { groupMoments } from '../../services/packetReplay'
import { PacketReplayBar } from '../PacketReplayBar'

const bounds = { from: 1_000_000, to: 1_060_000 }
const edges = [] as GraphEdge[]

const replay = (over: Partial<PacketReplay> = {}): PacketReplay => {
  const moment = groupMoments([
    { number: 41, t: 1_030_000, srcIp: '10.0.0.1', dstIp: '224.0.0.251', protocol: 'MDNS', conversationId: 'c', size: 90 },
    { number: 42, t: 1_030_000, srcIp: '10.0.0.2', dstIp: '224.0.0.251', protocol: 'MDNS', conversationId: 'c', size: 90 },
  ])[0]
  return {
    status: 'ready', moment, position: 41, total: 100, playing: false,
    play: vi.fn(), pause: vi.fn(), step: vi.fn(), seek: vi.fn(), speed: 2, setSpeed: vi.fn(),
    ...over,
  } as PacketReplay
}

describe('PacketReplayBar', () => {
  it('reads out the moment: packets that happened together, as one step', () => {
    render(<PacketReplayBar edges={edges} bounds={bounds} replay={replay()} onModeChange={() => {}} offGraph={1} />)
    const out = screen.getByTestId('replay-readout')
    expect(out).toHaveTextContent('Packets 41–42 of 100')
    expect(out).toHaveTextContent('2 packets at once: MDNS ×2')
    expect(out).toHaveTextContent('1 not on the graph')
  })

  it('steps with the buttons and the keyboard; Home seeks to the start', async () => {
    const user = userEvent.setup()
    const r = replay()
    render(<PacketReplayBar edges={edges} bounds={bounds} replay={r} onModeChange={() => {}} offGraph={0} />)
    await user.click(screen.getByRole('button', { name: 'Next moment' }))
    expect(r.step).toHaveBeenLastCalledWith(1)
    await user.click(screen.getByRole('button', { name: 'Previous moment' }))
    expect(r.step).toHaveBeenLastCalledWith(-1)
    screen.getByRole('slider', { name: 'Replay position' }).focus()
    await user.keyboard('{Shift>}{ArrowRight}{/Shift}')
    expect(r.step).toHaveBeenLastCalledWith(10)
    await user.keyboard('{Home}')
    expect(r.seek).toHaveBeenLastCalledWith(bounds.from)
    await user.click(screen.getByRole('button', { name: 'Play packet by packet' }))
    expect(r.play).toHaveBeenCalled()
  })

  it('says so when the capture has no packets to replay', () => {
    render(<PacketReplayBar edges={edges} bounds={bounds} replay={replay({ status: 'pruned', moment: null })} onModeChange={() => {}} offGraph={0} />)
    expect(screen.getByTestId('replay-readout')).toHaveTextContent("were pruned, so it can't be replayed")
    expect(screen.getByRole('button', { name: 'Play packet by packet' })).toBeDisabled()
  })

  it('switches back to the time window from its settings', async () => {
    const user = userEvent.setup()
    const onModeChange = vi.fn()
    render(<PacketReplayBar edges={edges} bounds={bounds} replay={replay()} onModeChange={onModeChange} offGraph={0} />)
    await user.click(screen.getByRole('button', { name: 'Replay settings' }))
    await user.click(await screen.findByRole('button', { name: 'Time window' }))
    expect(onModeChange).toHaveBeenCalledWith('window')
  })
})
