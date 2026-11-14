/** The home page's activity feed: captures and people's changes, newest first. */
import { describe, expect, it } from 'vitest';

import type { AuditLogEntry } from '@/features/me/meService';
import { ago, buildActivity, type ActivityFile } from '../RecentActivity';
import { retentionText } from '../StartPanel';

const NOW = Date.UTC(2026, 10, 14, 12, 0, 0);
const hoursAgo = (h: number) => new Date(NOW - h * 3600_000).toISOString();

const file = (
  id: string,
  h: number,
  status = 'COMPLETED',
  extra: Partial<ActivityFile> = {}
): ActivityFile => ({
  fileId: id,
  fileName: `${id}.pcap`,
  uploadedAt: hoursAgo(h),
  status,
  source: 'ANALYSIS',
  packetCount: 913,
  ...extra,
});

const change = (id: number, h: number): AuditLogEntry => ({
  id,
  at: hoursAgo(h),
  actor: 'system',
  action: 'detection-rule.create',
  targetType: 'detection-rule',
  targetId: 'r1',
  before: null,
  after: { name: 'Beacon' },
});

describe('buildActivity', () => {
  it('merges captures and changes, newest first', () => {
    const events = buildActivity([file('a', 3), file('b', 1)], [change(1, 2)], null, NOW);
    expect(events.map(e => e.key)).toEqual(['f-b', 'a-1', 'f-a']);
    expect(events[0]).toMatchObject({ tone: 'done', text: 'Analysed', meta: '913 packets' });
    expect(events[1].tone).toBe('change');
    expect(events[1].meta).toBe('Rule · by system');
  });

  it('warns about a capture that will be deleted soon, at the top', () => {
    const events = buildActivity([file('old', 10)], [], 12, NOW);
    expect(events[0]).toMatchObject({ tone: 'warn', text: 'Deleted in 2 hours:', whenText: '' });
  });

  it('does not warn when retention is off or the capture is a monitor snapshot', () => {
    expect(buildActivity([file('old', 10)], [], 0, NOW).some(e => e.tone === 'warn')).toBe(false);
    expect(
      buildActivity([file('snap', 10, 'COMPLETED', { source: 'MONITOR' })], [], 12, NOW).some(
        e => e.tone === 'warn'
      )
    ).toBe(false);
  });

  it('names failed and in-progress captures', () => {
    const events = buildActivity(
      [file('f', 1, 'FAILED'), file('p', 2, 'PROCESSING')],
      [],
      null,
      NOW
    );
    expect(events.map(e => e.tone)).toEqual(['failed', 'busy']);
  });

  it('keeps the six newest', () => {
    const files = Array.from({ length: 9 }, (_, i) => file(`f${i}`, i + 1));
    expect(buildActivity(files, [], null, NOW)).toHaveLength(6);
  });
});

describe('change lines', () => {
  const mapEdit = (id: number, h: number): AuditLogEntry => ({
    id,
    at: hoursAgo(h),
    actor: 'system',
    action: 'network-map.reset',
    targetType: 'network-map',
    targetId: 'a',
    before: { edits: [1, 2] },
    after: null,
  });

  it('folds a run of map edits into one line naming the capture', () => {
    const events = buildActivity(
      [file('a', 5)],
      [mapEdit(3, 1), mapEdit(2, 1.5), mapEdit(1, 2)],
      null,
      NOW
    );
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      text: 'Edited the network map of',
      link: { label: 'a.pcap', to: '/analysis/a/network-diagram' },
    });
    expect(events[0].meta).toMatch(/^3 changes, latest: /);
  });

  it('keeps at most three change lines, so captures stay in view', () => {
    const changes = [1, 2, 3, 4, 5].map(i => ({ ...change(i, i * 0.1), targetId: `r${i}` }));
    const events = buildActivity([file('a', 2), file('b', 3)], changes, null, NOW);
    expect(events.filter(e => e.tone === 'change')).toHaveLength(3);
    expect(events.filter(e => e.tone === 'done')).toHaveLength(2);
  });
});

describe('time words', () => {
  it('says how long ago', () => {
    expect(ago(NOW - 30_000, NOW)).toBe('just now');
    expect(ago(NOW - 5 * 60_000, NOW)).toBe('5 min ago');
    expect(ago(NOW - 3 * 3600_000, NOW)).toBe('3 h ago');
    expect(ago(NOW - 50 * 3600_000, NOW)).toBe('2 d ago');
  });

  it('says how long captures are kept', () => {
    expect(retentionText(12)).toBe('12 hours');
    expect(retentionText(24)).toBe('1 day');
    expect(retentionText(72)).toBe('3 days');
  });
});
