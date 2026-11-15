import { describe, expect, it } from 'vitest';
import type { TimelineDataPoint } from '@/types';
import {
  MAX_CHART_PROTOCOLS,
  OTHER_SERIES,
  selectProtocolSeries,
  toProtocolCounts,
} from '../protocolSeries';

const point = (protocols: Record<string, number>): TimelineDataPoint =>
  ({ timestamp: 0, packetCount: 0, bytes: 0, protocols }) as TimelineDataPoint;

const manyProtocols = (count: number) =>
  Object.fromEntries(
    Array.from({ length: count }, (_, i) => [`0X${i.toString(16).padStart(4, '0')}`, count - i])
  );

describe('selectProtocolSeries', () => {
  it('keeps the busiest protocols and flags the rest', () => {
    const series = selectProtocolSeries([point({ TCP: 1000, ...manyProtocols(390) })]);

    expect(series.protocols).toHaveLength(MAX_CHART_PROTOCOLS);
    expect(series.protocols[0]).toBe('TCP');
    expect(series.hasOther).toBe(true);
  });

  it('ranks across every bin, not within one', () => {
    const series = selectProtocolSeries([point({ UDP: 5, TCP: 4 }), point({ TCP: 4 })]);

    expect(series.protocols).toEqual(['TCP', 'UDP']);
  });

  it('adds no Other series when everything fits', () => {
    expect(selectProtocolSeries([point({ TCP: 2, UDP: 1 })]).hasOther).toBe(false);
  });

  it('folds the parser OTHER label into the Other series', () => {
    const series = selectProtocolSeries([point({ OTHER: 50, TCP: 1 })]);

    expect(series).toEqual({ protocols: ['TCP'], hasOther: true });
  });
});

describe('toProtocolCounts', () => {
  it('keeps the bin total when protocols are grouped', () => {
    const bins = [point({ TCP: 1000, ...manyProtocols(390) }), point({ '0X0000': 7 })];
    const series = selectProtocolSeries(bins);

    bins.forEach(bin => {
      const counts = toProtocolCounts(bin, series);
      const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
      expect(total).toBe(Object.values(bin.protocols).reduce((sum, count) => sum + count, 0));
    });
  });

  it('gives protocols missing from a bin a zero', () => {
    const series = { protocols: ['TCP'], hasOther: false };

    expect(toProtocolCounts(point({}), series)).toEqual({ TCP: 0 });
  });

  it('omits Other when nothing was grouped', () => {
    const counts = toProtocolCounts(point({ TCP: 1 }), { protocols: ['TCP'], hasOther: false });

    expect(counts).not.toHaveProperty(OTHER_SERIES);
  });
});
