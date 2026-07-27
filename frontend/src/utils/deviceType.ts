import type { DeviceType } from '@/types';

interface DeviceTypeConfig {
  label: string;
  color: string;
}

const DEVICE_TYPE_CONFIG: Partial<Record<DeviceType, DeviceTypeConfig>> = {
  ROUTER:         { label: 'Router',           color: '#f97316' }, // orange
  MOBILE:         { label: 'Mobile',           color: '#8b5cf6' }, // violet
  LAPTOP_DESKTOP: { label: 'Laptop / Desktop', color: '#3b82f6' }, // blue
  SERVER:         { label: 'Server',           color: '#10b981' }, // emerald
  IOT:            { label: 'IoT Device',       color: '#ec4899' }, // pink
  // Service-server family — a cohesive cool ramp (sky → indigo → purple), kept clearly off the
  // generic SERVER green so they're easy to tell apart on the diagram.
  DNS_SERVER:     { label: 'DNS Server',       color: '#0ea5e9' }, // sky
  WEB_SERVER:     { label: 'Web Server',       color: '#6366f1' }, // indigo
  API_SERVER:     { label: 'API Server',       color: '#a855f7' }, // purple
  // Pure L2 nodes (switches/bridges) have no adjudicated identity or device type of their own,
  // but are still a distinct filterable identity. Teal matches the l2-device node colour.
  L2_DEVICE:      { label: 'L2 Device',        color: '#1abc9c' }, // teal
  UNKNOWN:        { label: 'Unknown',          color: '#6b7280' }, // gray
};

const DEFAULT_COLOR = '#6b7280';

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
  return DEVICE_TYPE_CONFIG[deviceType]?.color ?? DEFAULT_COLOR;
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

const DEVICE_TYPE_ICONS: Partial<Record<DeviceType, string>> = {
  ROUTER:         'bi-router',
  MOBILE:         'bi-phone',
  LAPTOP_DESKTOP: 'bi-laptop',
  SERVER:         'bi-server',
  IOT:            'bi-cpu',
  DNS_SERVER:     'bi-hdd-network',
  WEB_SERVER:     'bi-globe',
  API_SERVER:     'bi-hdd-stack',
  L2_DEVICE:      'bi-ethernet',
};

/**
 * Returns the Bootstrap Icon class name for the device type.
 */
export function deviceTypeIcon(deviceType: DeviceType): string {
  return DEVICE_TYPE_ICONS[deviceType] ?? 'bi-question-circle';
}

/** All canonical device type values shown in filter UIs, in display order. */
export const DEVICE_TYPES: DeviceType[] = [
  'ROUTER',
  'MOBILE',
  'LAPTOP_DESKTOP',
  'SERVER',
  'IOT',
  'DNS_SERVER',
  'WEB_SERVER',
  'API_SERVER',
  'L2_DEVICE',
  'UNKNOWN',
];

/**
 * The single canonical identity key for a graph node — the one taxonomy the Node Identity filter
 * keys on (#499/#537: "Identity owns the verdict"). It replaces the old two parallel filter
 * dimensions (`nodeType` + `deviceType`) that rendered the same role twice ("Router / Gateway"
 * vs "Router", "Web Server" twice, …).
 *
 * Resolution order mirrors the display authority in networkService:
 *   1. the adjudicated identity label (already a DeviceType value — WEB_SERVER, ROUTER, …)
 *   2. else the machine device classification (skipping the non-committal UNKNOWN)
 *   3. else the structural L2 fallback for pure switches/bridges
 *   4. else UNKNOWN
 *
 * The result is always a DeviceType (plus 'L2_DEVICE'), so deviceTypeLabel/Color/Icon render it
 * with no extra config. Note this is *finer* than the rendered `nodeType`, which collapses the
 * Mobile/IoT/Laptop family into "client" — filtering here keeps them distinct.
 */
export function nodeIdentityKey(node: {
  identityLabel?: string;
  deviceType?: string;
  nodeType?: string;
}): string {
  if (node.identityLabel) return node.identityLabel;
  if (node.deviceType && node.deviceType !== 'UNKNOWN') return node.deviceType;
  if (node.nodeType === 'l2-device') return 'L2_DEVICE';
  return 'UNKNOWN';
}
