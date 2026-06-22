import { parseDateTime } from '../dateUtils';

describe('parseDateTime', () => {
  it('parses an ISO date string in UTC', () => {
    const ts = parseDateTime('2025-06-15T10:30:00Z');
    expect(ts).toBe(1749983400000);
  });

  it('parses a Spring LocalDateTime array [Y, M, D, h, m, s]', () => {
    const ts = parseDateTime([2025, 6, 15, 10, 30, 0]);
    const date = new Date(ts);
    expect(date.getFullYear()).toBe(2025);
    expect(date.getMonth()).toBe(5);
    expect(date.getDate()).toBe(15);
    expect(date.getHours()).toBe(10);
    expect(date.getMinutes()).toBe(30);
    expect(date.getSeconds()).toBe(0);
  });

  it('parses a 5-element array (seconds omitted)', () => {
    const ts = parseDateTime([2025, 6, 15, 10, 30]);
    const date = new Date(ts);
    expect(date.getFullYear()).toBe(2025);
    expect(date.getMonth()).toBe(5);
    expect(date.getDate()).toBe(15);
    expect(date.getHours()).toBe(10);
    expect(date.getMinutes()).toBe(30);
    expect(date.getSeconds()).toBe(0);
  });

  it('returns 0 for a short array', () => {
    expect(parseDateTime([2025, 6])).toBe(0);
  });

  it('returns NaN for an invalid date string', () => {
    expect(parseDateTime('invalid-date')).toBeNaN();
  });
});
