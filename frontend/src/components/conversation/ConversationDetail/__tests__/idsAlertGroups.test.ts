import { describe, expect, it } from 'vitest';
import { alertsFiredNote, groupIdsAlerts } from '../idsAlertGroups';
import type { IdsAlert } from '@/types';

const checkin = (time: number): IdsAlert => ({
  time,
  srcIp: '10.11.26.183',
  sid: 2035892,
  signature: 'ET INFO NetSupport Remote Admin Checkin',
  httpMethod: 'POST',
  httpUrl: 'http://194.180.191.64/fakeurl.htm',
});

describe('groupIdsAlerts (#1265)', () => {
  it('folds repeats into one row with a count and the time span', () => {
    const groups = groupIdsAlerts([checkin(3000), checkin(1000), checkin(2000)]);
    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({ count: 3, from: 1000, to: 3000 });
  });

  it('keeps the server\'s reply and a different request apart', () => {
    const reply: IdsAlert = { srcIp: '194.180.191.64', sid: 2035892, signature: 'x' };
    const other: IdsAlert = { ...checkin(5000), httpUrl: 'http://194.180.191.64/other' };
    expect(groupIdsAlerts([checkin(1000), reply, other])).toHaveLength(3);
  });
});

describe('alertsFiredNote (#1284)', () => {
  it('is the count when every alert has a record', () => {
    expect(alertsFiredNote(3, 3)).toBe('3 fired');
    expect(alertsFiredNote(3, null)).toBe('3 fired');
  });

  it('says the rows are only the first when the records stopped at their cap', () => {
    expect(alertsFiredNote(100, 4512)).toBe('4,512 fired · first 100 shown');
  });

  it('says when none were kept', () => {
    expect(alertsFiredNote(0, 7)).toBe('7 fired · no records kept');
  });
});
