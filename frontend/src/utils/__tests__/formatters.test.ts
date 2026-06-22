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
