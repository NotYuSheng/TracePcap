import type { DeviceType } from '@/types';

/**
 * Returns a Unicode emoji icon representing the device type.
 * Used in ConversationList, ConversationDetail, and NetworkDiagram.
 */
export function deviceTypeIcon(deviceType: DeviceType): string {
  switch (deviceType) {
    case 'ROUTER':
      return '🔀';
    case 'MOBILE':
      return '📱';
    case 'LAPTOP_DESKTOP':
      return '💻';
    case 'SERVER':
      return '🖥️';
    case 'IOT':
      return '🔌';
    case 'UNKNOWN':
    default:
      return '❓';
  }
}

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

/** All canonical device type values shown in filter UIs. */
export const DEVICE_TYPES: DeviceType[] = [
  'ROUTER',
  'MOBILE',
  'LAPTOP_DESKTOP',
  'SERVER',
  'IOT',
  'UNKNOWN',
];
