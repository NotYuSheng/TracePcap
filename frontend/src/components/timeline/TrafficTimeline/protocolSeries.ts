import type { TimelineDataPoint } from '@/types';

/**
 * The most protocols the chart draws individually. A capture can hold hundreds of distinct labels
 * (tshark names an unknown ethertype by its hex value, e.g. 0x2573), and one stacked series per
 * label floods the legend and bogs the chart down.
 */
export const MAX_CHART_PROTOCOLS = 10;

export const OTHER_SERIES = 'Other';

export interface ProtocolSeries {
  /** The protocols drawn individually, busiest first. */
  protocols: string[];
  /** Whether any traffic falls outside {@link protocols}. */
  hasOther: boolean;
}

/** Picks the busiest protocols across all bins. The parser's own OTHER label joins the rest. */
export function selectProtocolSeries(data: TimelineDataPoint[]): ProtocolSeries {
  const totals = new Map<string, number>();
  data.forEach(point => {
    Object.entries(point.protocols ?? {}).forEach(([proto, count]) => {
      totals.set(proto, (totals.get(proto) ?? 0) + count);
    });
  });
  const ranked = [...totals.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([proto]) => proto)
    .filter(proto => proto.toUpperCase() !== OTHER_SERIES.toUpperCase());
  const protocols = ranked.slice(0, MAX_CHART_PROTOCOLS);
  return { protocols, hasOther: totals.size > protocols.length };
}

/** One chart row for a bin: a count per drawn protocol, plus the remainder under Other. */
export function toProtocolCounts(
  point: TimelineDataPoint,
  { protocols, hasOther }: ProtocolSeries
): Record<string, number> {
  const counts: Record<string, number> = {};
  protocols.forEach(proto => {
    counts[proto] = point.protocols?.[proto] ?? 0;
  });
  if (hasOther) {
    const shown = new Set(protocols);
    counts[OTHER_SERIES] = Object.entries(point.protocols ?? {})
      .filter(([proto]) => !shown.has(proto))
      .reduce((sum, [, count]) => sum + count, 0);
  }
  return counts;
}
