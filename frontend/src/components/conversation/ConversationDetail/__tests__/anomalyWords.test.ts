import { describe, expect, it } from 'vitest';
import { anomalyWords, groupAnomalies } from '../anomalyWords';

describe('anomalyWords (#1268)', () => {
  it('explains a known anomaly in plain words', () => {
    expect(anomalyWords('APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION')).toContain('one direction only');
  });

  it('makes an unknown one readable', () => {
    expect(anomalyWords('STREAM_PKT_INVALID_ACK')).toBe('Stream pkt invalid ack.');
  });

  it('folds repeats', () => {
    const a = { event: 'X', appProto: 'smb', srcIp: '10.0.0.1' };
    expect(groupAnomalies([a, a, { ...a, appProto: 'http' }]).map((g) => g.count)).toEqual([2, 1]);
  });
});
