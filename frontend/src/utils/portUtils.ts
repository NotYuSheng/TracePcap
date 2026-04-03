/**
 * Maps a well-known destination port number to a human-readable service label.
 * Returns null for unknown / ephemeral ports.
 */
export function portToServiceLabel(port: number): string | null {
  if (port === 80 || port === 8080) return 'Web Server';
  if (port === 443 || port === 8443) return 'Web Server (HTTPS)';
  if (port === 53) return 'DNS Server';
  if (port === 22) return 'SSH Server';
  if (port === 21) return 'FTP Server';
  if (port === 25 || port === 587 || port === 465) return 'Mail Server';
  if (port === 67 || port === 68) return 'DHCP Server';
  if (port === 123) return 'NTP Server';
  if (port === 3306 || port === 5432 || port === 1433 || port === 27017) return 'Database Server';
  return null;
}
