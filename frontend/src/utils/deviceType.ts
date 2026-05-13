import type { DeviceType } from '@/types';

interface DeviceTypeConfig {
  label: string;
  color: string;
}

const DEVICE_TYPE_CONFIG: Record<string, DeviceTypeConfig> = {
  ROUTER:         { label: 'Router',           color: '#f97316' }, // orange
  MOBILE:         { label: 'Mobile',           color: '#8b5cf6' }, // violet
  LAPTOP_DESKTOP: { label: 'Laptop / Desktop', color: '#3b82f6' }, // blue
  SERVER:         { label: 'Server',           color: '#10b981' }, // emerald
  IOT:            { label: 'IoT Device',       color: '#ec4899' }, // pink
  UNKNOWN:        { label: 'Unknown',          color: '#6b7280' }, // gray
};

const DEFAULT_CONFIG: DeviceTypeConfig = { label: '', color: '#6b7280' };

/**
 * Returns a human-readable label for the device type.
 */
export function deviceTypeLabel(deviceType: DeviceType): string {
  return DEVICE_TYPE_CONFIG[deviceType]?.label ?? deviceType; // custom YAML override values pass through as-is
}

/**
 * Returns a hex colour for the device type (used in NetworkDiagram nodes).
 */
export function deviceTypeColor(deviceType: DeviceType): string {
  return (DEVICE_TYPE_CONFIG[deviceType] ?? DEFAULT_CONFIG).color;
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
