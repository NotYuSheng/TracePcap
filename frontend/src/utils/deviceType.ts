import type { DeviceType } from '@/types';

/**
 * Returns a human-readable label for the device type.
 */
export function deviceTypeLabel(deviceType: DeviceType): string {
  switch (deviceType) {
    case 'ROUTER':
      return 'Router';
    case 'MOBILE':
      return 'Mobile';
    case 'LAPTOP_DESKTOP':
      return 'Laptop / Desktop';
    case 'SERVER':
      return 'Server';
    case 'IOT':
      return 'IoT Device';
    case 'UNKNOWN':
      return 'Unknown';
    default:
      return deviceType; // custom YAML override values pass through as-is
  }
}

/**
 * Returns a hex colour for the device type (used in NetworkDiagram nodes).
 */
export function deviceTypeColor(deviceType: DeviceType): string {
  switch (deviceType) {
    case 'ROUTER':
      return '#f97316'; // orange
    case 'MOBILE':
      return '#8b5cf6'; // violet
    case 'LAPTOP_DESKTOP':
      return '#3b82f6'; // blue
    case 'SERVER':
      return '#10b981'; // emerald
    case 'IOT':
      return '#ec4899'; // pink
    case 'UNKNOWN':
    default:
      return '#6b7280'; // gray
  }
}

/**
 * Maps a confidence percentage (0–100) to a human-readable label.
 * Used in classification popups to describe how reliable the device detection is.
 */
export function confidenceLevel(pct: number): string {
  if (pct >= 75) return 'Strong';
  if (pct >= 50) return 'Moderate';
  if (pct >= 25) return 'Low';
  return 'Uncertain';
}

/**
 * Builds the list of human-readable signal strings that explain why a host
 * was classified as a particular device type. Used in classification popups.
 */
export function buildDeviceSignals(info: {
  manufacturer?: string;
  ttl?: number;
  confidence: number;
}): string[] {
  const signals: string[] = [];
  if (info.manufacturer) signals.push(`MAC OUI matched: ${info.manufacturer}`);
  if (info.ttl != null) {
    const os =
      info.ttl <= 64
        ? 'Linux / Android / iOS'
        : info.ttl <= 128
          ? 'Windows'
          : 'Network device (Cisco / BSD)';
    signals.push(`TTL ${info.ttl} → ${os}`);
  }
  if (info.confidence >= 60) signals.push('Application traffic profile analysed');
  if (info.confidence >= 25) signals.push('Network traffic patterns analysed');
  return signals;
}

/** All canonical device type values shown in filter UIs. */
export const DEVICE_TYPES: DeviceType[] = [
  'ROUTER',
  'MOBILE',
  'LAPTOP_DESKTOP',
  'SERVER',
  'IOT',
  'UNKNOWN',
];
