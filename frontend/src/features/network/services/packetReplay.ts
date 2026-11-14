import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';

/**
 * Packet replay: the capture played back on the network graph one moment at a time, where a moment
 * is every packet captured at (about) the same instant. A broadcast, a multicast answered by many,
 * a burst within one millisecond: those happen together, so they play together.
 */

export interface ReplayPacket {
  number: number;
  /** Epoch ms, read the same way as conversation times (capture-local). */
  t: number;
  srcIp: string;
  srcPort?: number | null;
  dstIp: string;
  dstPort?: number | null;
  protocol: string;
  size?: number | null;
  conversationId: string;
  info?: string | null;
}

export interface Moment {
  t: number;
  packets: ReplayPacket[];
}

export interface ReplayPage {
  packets: ReplayPacket[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

interface ApiPacket extends Omit<ReplayPacket, 't'> {
  timestamp: string | number[];
}

/** Packets this close together (ms) count as one moment. */
export const MOMENT_MS = 1;

/** Groups packets (in capture order) into moments. */
export function groupMoments(packets: ReplayPacket[], epsMs = MOMENT_MS): Moment[] {
  const out: Moment[] = [];
  for (const p of packets) {
    const last = out[out.length - 1];
    if (last && Math.abs(p.t - last.t) <= epsMs) last.packets.push(p);
    else out.push({ t: p.t, packets: [p] });
  }
  return out;
}

/** The index of the moment holding packet `number` (or the first after it). */
export function momentIndexOf(moments: Moment[], number: number): number {
  let lo = 0;
  let hi = moments.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const last = moments[mid].packets[moments[mid].packets.length - 1].number;
    if (last < number) lo = mid + 1;
    else hi = mid;
  }
  return Math.max(0, lo);
}

/** A conversation's two ends on the graph, and which address is the edge's source end. */
export interface ConversationEnds {
  source: string;
  target: string;
  sourceIp: string;
}

export interface Flight {
  from: string;
  to: string;
  protocol: string;
}

/** Where each packet of a moment flies on the graph. Packets whose conversation isn't drawn have none. */
export function flightsFor(moment: Moment, ends: Map<string, ConversationEnds>): Flight[] {
  const out: Flight[] = [];
  for (const p of moment.packets) {
    const e = ends.get(p.conversationId);
    if (!e) continue;
    const forward = p.srcIp === e.sourceIp;
    out.push({ from: forward ? e.source : e.target, to: forward ? e.target : e.source, protocol: p.protocol });
  }
  return out;
}

/** One line for a packet: "TCP 10.0.0.5:51334 → 10.0.0.9:445 · 74 B · [SYN]". */
export function describePacket(p: ReplayPacket): string {
  const end = (ip: string, port?: number | null) => (port != null ? `${ip}:${port}` : ip);
  const parts = [`${p.protocol} ${end(p.srcIp, p.srcPort)} → ${end(p.dstIp, p.dstPort)}`];
  if (p.size != null) parts.push(`${p.size} B`);
  if (p.info) parts.push(p.info);
  return parts.join(' · ');
}

/** A moment of several packets: "3 packets at once: DNS ×2, ARP". */
export function describeMoment(m: Moment): string {
  if (m.packets.length === 1) return describePacket(m.packets[0]);
  const counts = new Map<string, number>();
  for (const p of m.packets) counts.set(p.protocol, (counts.get(p.protocol) ?? 0) + 1);
  const what = [...counts].map(([proto, n]) => (n > 1 ? `${proto} ×${n}` : proto)).join(', ');
  return `${m.packets.length} packets at once: ${what}`;
}

/** Local wall-clock ISO (no zone), the way capture times are stored and read. */
export function localIso(ms: number): string {
  const d = new Date(ms);
  const z = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}-${z(d.getMonth() + 1)}-${z(d.getDate())}T${z(d.getHours())}:${z(d.getMinutes())}:${z(d.getSeconds())}.${z(d.getMilliseconds(), 3)}`;
}

export const packetReplayService = {
  /** A page of packets; with `at` (epoch ms), the page holding the first packet at or after it. */
  async page(fileId: string, page: number, pageSize: number, at?: number): Promise<ReplayPage> {
    const params: Record<string, string | number> = { page, pageSize };
    if (at != null) params.at = localIso(at);
    const res = await apiClient.get<{ data: ApiPacket[]; page: number; pageSize: number; total: number; totalPages: number }>(
      API_ENDPOINTS.FILE_PACKETS(fileId),
      { params },
    );
    const { data, ...rest } = res.data;
    return { ...rest, packets: data.map(({ timestamp, ...p }) => ({ ...p, t: parseDateTime(timestamp) })) };
  },
};
