import { useMemo, useState, type ReactNode } from 'react';
import type { GraphEdge, GraphNode } from '@/features/network/types';
import { usePacketReplay } from '@/features/network/hooks/usePacketReplay';
import { PacketReplayBar } from '@/features/network/components/PacketReplayBar';
import { TimeScrubber } from '@/features/network/components/TimeScrubber';
import type { AxisMode } from '@/features/network/components/PlayByControl';
import { flightsFor, type ConversationEnds } from '@/features/network/services/packetReplay';
import { getProtocolColor } from '@/features/network/constants';
import {
  activeInWindow,
  timeBounds,
  unseenByWindowEnd,
  type TimeWindow,
} from '@/features/network/services/timeWindow';

/**
 * A network map's motion, ready to hand to NetworkGraph: traffic dots along the edges (unless the
 * system asks for reduced motion), and, with `controls`, the bar under the graph that plays the
 * capture by a sliding time window or packet by packet.
 *
 * The window and play mode belong to one capture: remount (key) the caller per capture to reset them.
 */
export function useMapPlayback(
  fileId: string,
  nodes: GraphNode[],
  edges: GraphEdge[],
  { controls = true }: { controls?: boolean } = {}
) {
  const [timeWindow, setTimeWindow] = useState<TimeWindow | null>(null);
  const [animateTraffic, setAnimateTraffic] = useState(
    () => !(typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches)
  );
  const [appearWhenSeen, setAppearWhenSeen] = useState(false);
  const [unseenStyle, setUnseenStyle] = useState<'hide' | 'faint'>('hide');
  const [axisMode, setAxisMode] = useState<AxisMode>('window');

  const bounds = useMemo(() => timeBounds(edges), [edges]);
  const replay = usePacketReplay(fileId, controls && axisMode === 'packets');
  const replayT = axisMode === 'packets' ? replay.moment?.t : undefined;
  const axisWindow = useMemo<TimeWindow | null>(
    () => (axisMode === 'packets' ? (replayT != null ? { from: replayT, to: replayT } : null) : timeWindow),
    [axisMode, replayT, timeWindow]
  );
  const windowActive = useMemo(() => {
    if (!axisWindow) return null;
    const active = { ...activeInWindow(edges, axisWindow), window: axisWindow };
    if (!appearWhenSeen) return active;
    const unseen = unseenByWindowEnd(edges, axisWindow);
    return unseenStyle === 'faint' ? { ...active, faintNodeIds: unseen } : { ...active, hiddenNodeIds: unseen };
  }, [edges, axisWindow, appearWhenSeen, unseenStyle]);

  const conversationEnds = useMemo(() => {
    const ipOf = new Map(nodes.map(n => [n.id, n.data.ip]));
    const m = new Map<string, ConversationEnds>();
    for (const e of edges) {
      m.set(e.data.conversationId, { source: e.source, target: e.target, sourceIp: ipOf.get(e.source) ?? '' });
    }
    return m;
  }, [edges, nodes]);
  const packetFlights = useMemo(() => {
    const m = replay.moment;
    if (axisMode !== 'packets' || !m) return null;
    const flights = flightsFor(m, conversationEnds).map(f => ({
      from: f.from,
      to: f.to,
      color: getProtocolColor(f.protocol),
    }));
    return {
      key: m.packets[0].number,
      flights,
      durationMs: Math.min(900, Math.max(180, 800 / replay.speed)),
      offGraph: m.packets.length - flights.length,
    };
  }, [axisMode, replay.moment, replay.speed, conversationEnds]);

  const hasSpan = !!bounds && bounds.to > bounds.from;
  let bottomBar: ReactNode = undefined;
  if (controls && hasSpan && bounds) {
    bottomBar =
      axisMode === 'packets' ? (
        <PacketReplayBar
          edges={edges}
          bounds={bounds}
          replay={replay}
          onModeChange={setAxisMode}
          offGraph={packetFlights?.offGraph ?? 0}
        />
      ) : (
        <TimeScrubber
          onModeChange={setAxisMode}
          edges={edges}
          bounds={bounds}
          window={timeWindow}
          onWindowChange={setTimeWindow}
          activeCount={windowActive ? windowActive.edgeIds.size : edges.length}
          animate={animateTraffic}
          onAnimateChange={setAnimateTraffic}
          appearWhenSeen={appearWhenSeen}
          onAppearWhenSeenChange={setAppearWhenSeen}
          unseenStyle={unseenStyle}
          onUnseenStyleChange={setUnseenStyle}
        />
      );
  }

  /** Spread onto NetworkGraph. */
  return {
    activeInWindow: windowActive,
    animateTraffic: animateTraffic && axisMode === 'window',
    packetFlights,
    bottomBar,
  };
}
