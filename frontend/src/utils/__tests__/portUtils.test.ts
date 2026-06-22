import { portToServiceLabel } from '../portUtils';

describe('portToServiceLabel', () => {
  it.each([
    [80, 'Web Server'],
    [8080, 'Web Server'],
    [443, 'Web Server (HTTPS)'],
    [8443, 'Web Server (HTTPS)'],
    [53, 'DNS Server'],
    [22, 'SSH Server'],
    [21, 'FTP Server'],
    [25, 'Mail Server'],
    [587, 'Mail Server'],
    [465, 'Mail Server'],
    [67, 'DHCP Server'],
    [68, 'DHCP Server'],
    [123, 'NTP Server'],
    [3306, 'Database Server'],
    [5432, 'Database Server'],
    [1433, 'Database Server'],
    [27017, 'Database Server'],
  ])('maps port %i to "%s"', (port, expected) => {
    expect(portToServiceLabel(port)).toBe(expected);
  });

  it('returns null for unknown ports', () => {
    expect(portToServiceLabel(9999)).toBeNull();
    expect(portToServiceLabel(0)).toBeNull();
  });
});
