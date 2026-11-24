import type { ProtocolAnomaly } from '@/types';

/** Plain words for the anomalies Suricata reports most (#1268); others fall back to their name. */
const KNOWN: Record<string, string> = {
  APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION:
    'The protocol was recognised in one direction only: the other side\'s packets may be missing.',
  APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS: 'Each side spoke a different protocol.',
  APPLAYER_WRONG_DIRECTION_FIRST_DATA: 'The server sent data first, unusual for this protocol.',
  APPLAYER_PROTO_DETECTION_SKIPPED: 'Too little data to recognise the protocol.',
  APPLAYER_UNEXPECTED_PROTOCOL: 'Traffic didn\'t match the protocol the session started with.',
};

/** "Protocol seen in one direction only…", or "Applayer detect protocol only one direction". */
export function anomalyWords(event: string): string {
  if (KNOWN[event]) return KNOWN[event];
  const words = event.toLowerCase().replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1) + '.';
}

/** Repeats of one anomaly folded into one row with a count; first-seen order. */
export function groupAnomalies(list: ProtocolAnomaly[]): Array<{ first: ProtocolAnomaly; count: number }> {
  const groups = new Map<string, { first: ProtocolAnomaly; count: number }>();
  for (const a of list) {
    const key = [a.event, a.appProto, a.srcIp].join('|');
    const g = groups.get(key);
    if (g) g.count += 1;
    else groups.set(key, { first: a, count: 1 });
  }
  return [...groups.values()];
}
