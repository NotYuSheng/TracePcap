/** Convert a Spring LocalDateTime (array or ISO string) to a millisecond timestamp. */
export const parseDateTime = (dt: string | number[]): number => {
  if (typeof dt === 'string') return new Date(dt).getTime();
  if (Array.isArray(dt) && dt.length >= 6) {
    return new Date(dt[0], dt[1] - 1, dt[2], dt[3], dt[4], dt[5]).getTime();
  }
  return 0;
};
