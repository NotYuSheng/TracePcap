import { parseDateTime } from '../dateUtils';

describe('parseDateTime', () => {
  it('parses an ISO date string', () => {
    const ts = parseDateTime('2025-06-15T10:30:00');
    expect(ts).toBe(new Date('2025-06-15T10:30:00').getTime());
  });

  it('parses a Spring LocalDateTime array [Y, M, D, h, m, s]', () => {
    const ts = parseDateTime([2025, 6, 15, 10, 30, 0]);
    expect(ts).toBe(new Date(2025, 5, 15, 10, 30, 0).getTime());
  });

  it('returns 0 for a short array', () => {
    expect(parseDateTime([2025, 6])).toBe(0);
  });
});
