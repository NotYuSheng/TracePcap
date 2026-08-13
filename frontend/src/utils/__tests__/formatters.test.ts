import {
  formatBytes,
  formatDuration,
  formatNumber,
  formatProtocol,
  formatIpPort,
  formatPercentage,
} from '../formatters';

describe('formatBytes', () => {
  it('returns "0 B" for zero', () => {
    expect(formatBytes(0)).toBe('0 B');
  });

  it('formats bytes below 1 KB', () => {
    expect(formatBytes(512)).toBe('512 B');
  });

  it('formats kilobytes', () => {
    expect(formatBytes(1024)).toBe('1.00 KB');
    expect(formatBytes(1536)).toBe('1.50 KB');
  });

  it('formats megabytes', () => {
    expect(formatBytes(1048576)).toBe('1.00 MB');
  });

  it('formats gigabytes', () => {
    expect(formatBytes(1073741824)).toBe('1.00 GB');
  });
});

describe('formatBytes at scale', () => {
  // Seven implementations existed, each with its own ceiling. Two indexed past the end of
  // their unit array; the rest silently topped out. Production captures reach tens of TB,
  // so both failure modes were reachable on real data.
  it('formats terabytes rather than thousands of gigabytes', () => {
    expect(formatBytes(2 * 1024 ** 4)).toBe('2.00 TB')
  })

  it('formats the ~25TB production scale', () => {
    expect(formatBytes(25.62 * 1024 ** 4)).toBe('25.62 TB')
  })

  it('formats petabytes', () => {
    expect(formatBytes(3 * 1024 ** 5)).toBe('3.00 PB')
  })

  it('clamps beyond the largest unit instead of rendering "undefined"', () => {
    // The actual bug: sizes[i] was undefined past the end of the array, so the UI showed
    // "1.0 undefined". Clamping matters more than the unit list being long enough, because
    // extending the list only moves the boundary.
    const huge = formatBytes(1024 ** 7)
    expect(huge).not.toContain('undefined')
    expect(huge).toContain('PB')
  })

  it('never renders NaN or Infinity', () => {
    expect(formatBytes(Number.NaN)).toBe('0 B')
    expect(formatBytes(Number.POSITIVE_INFINITY)).toBe('0 B')
  })

  it('keeps the sign on a negative delta', () => {
    expect(formatBytes(-1536)).toBe('-1.50 KB')
  })
})

describe('formatDuration', () => {
  it('formats sub-second durations', () => {
    expect(formatDuration(500)).toBe('500ms');
  });

  it('formats seconds', () => {
    expect(formatDuration(5000)).toBe('5s');
  });

  it('formats minutes and seconds', () => {
    expect(formatDuration(150000)).toBe('2m 30s');
  });

  it('formats hours and minutes', () => {
    expect(formatDuration(3660000)).toBe('1h 1m');
  });

  it('handles boundary values', () => {
    expect(formatDuration(0)).toBe('0ms');
    expect(formatDuration(60000)).toBe('1m 0s');
    expect(formatDuration(3600000)).toBe('1h 0m');
  });
});

describe('formatNumber', () => {
  it('adds thousand separators', () => {
    expect(formatNumber(125432)).toBe('125,432');
  });

  it('leaves small numbers unchanged', () => {
    expect(formatNumber(42)).toBe('42');
  });
});

describe('formatProtocol', () => {
  it('uppercases protocol names', () => {
    expect(formatProtocol('tcp')).toBe('TCP');
    expect(formatProtocol('udp')).toBe('UDP');
  });
});

describe('formatIpPort', () => {
  it('returns IP with port when port is provided', () => {
    expect(formatIpPort('192.168.1.1', 80)).toBe('192.168.1.1:80');
  });

  it('returns IP only when port is omitted', () => {
    expect(formatIpPort('10.0.0.1')).toBe('10.0.0.1');
  });

  it('wraps IPv6 addresses in brackets when port is provided', () => {
    expect(formatIpPort('2001:db8::1', 80)).toBe('[2001:db8::1]:80');
  });

  it('returns bare IPv6 when port is omitted', () => {
    expect(formatIpPort('2001:db8::1')).toBe('2001:db8::1');
  });
});

describe('formatPercentage', () => {
  it('converts decimal to percentage string', () => {
    expect(formatPercentage(0.455)).toBe('45.5%');
  });

  it('respects custom decimal places', () => {
    expect(formatPercentage(0.33333, 2)).toBe('33.33%');
  });

  it('handles zero', () => {
    expect(formatPercentage(0)).toBe('0.0%');
  });
});
