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
  DNS_SERVER:     { label: 'DNS Server',       color: '#0ea5e9' }, // sky
  WEB_SERVER:     { label: 'Web Server',       color: '#14b8a6' }, // teal
  API_SERVER:     { label: 'API Server',       color: '#6366f1' }, // indigo
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

export interface DeviceSignalInfo {
  manufacturer?: string;
  ttl?: number;
  confidence: number;
  deviceType?: string;
  /** Apps seen in conversations for this host */
  apps?: string[];
  /** Service roles this host was detected serving (e.g. ["dns"]). */
  serviceRoles?: string[];
  /** Number of distinct peer IPs */
  peerCount?: number;
  /** Number of conversations initiated by this host */
  initiatedCount?: number;
  /** Total conversations involving this host */
  conversationCount?: number;
}

export interface DeviceSignalResult {
  /** Signals that actually fired, with point values */
  fired: string[];
  /** Suggestions for signals that could not be evaluated */
  missing: string[];
}

// App categories inferred from app name patterns (mirrors DeviceClassifierService heuristics)
const MOBILE_APPS = ['whatsapp', 'instagram', 'tiktok', 'snapchat', 'facebook', 'messenger', 'telegram', 'signal', 'viber', 'line'];
const SERVER_APPS = ['apache', 'nginx', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'ssh', 'ftp', 'smtp', 'imap', 'pop3'];
const LAPTOP_APPS = ['zoom', 'teams', 'slack', 'dropbox', 'skype', 'webex', 'googlemeet', 'outlook'];
const ROUTER_APPS = ['ospf', 'bgp', 'snmp', 'stp', 'lldp', 'ntp'];

function matchesAny(app: string, list: string[]): boolean {
  const lower = app.toLowerCase();
  return list.some(k => lower.includes(k));
}

// Human-readable device type labels for signal messages
const TYPE_LABEL: Record<string, string> = {
  ROUTER: 'Router',
  MOBILE: 'Mobile',
  LAPTOP_DESKTOP: 'Laptop/Desktop',
  SERVER: 'Server',
  IOT: 'IoT',
};

function typeLabel(t?: string): string {
  return (t && TYPE_LABEL[t.toUpperCase()]) ?? t ?? 'classified type';
}

/**
 * Reconstructs the scoring signals that contributed to a device classification.
 * Confidence is derived from the margin between the top two competing types,
 * not from the raw score — so signals explain what evidence tipped the balance.
 * Returns fired signals and suggestions for missing data.
 */
export function buildDeviceSignals(info: DeviceSignalInfo): DeviceSignalResult {
  const fired: string[] = [];
  const missing: string[] = [];
  const dtype = typeLabel(info.deviceType);

  // ── Service roles (authoritative) ─────────────────────────────────────────
  if (info.serviceRoles?.includes('dns')) {
    fired.push('Answered DNS queries → DNS Server (authoritative — outranks heuristics)');
  }
  if (info.serviceRoles?.includes('api')) {
    fired.push('Served an HTTP API → API Server (authoritative — outranks heuristics)');
  }
  if (info.serviceRoles?.includes('web')) {
    fired.push('Served HTTP/TLS → Web Server (authoritative — outranks heuristics)');
  }

  // ── OUI / manufacturer ──────────────────────────────────────────────────
  if (info.manufacturer) {
    fired.push(`MAC OUI matched "${info.manufacturer}" → +40 to ${dtype} (largest single signal)`);
  } else {
    missing.push('MAC OUI not resolved — would add +40 to the matched type (largest single signal)');
  }

  // ── TTL heuristic ───────────────────────────────────────────────────────
  if (info.ttl != null) {
    if (info.ttl >= 120 && info.ttl <= 128) {
      fired.push(`TTL ${info.ttl} (Windows range) → +30 to Laptop/Desktop`);
    } else if (info.ttl >= 250) {
      fired.push(`TTL ${info.ttl} (network device range) → +30 to Router`);
    } else if (info.ttl >= 55 && info.ttl <= 70) {
      fired.push(`TTL ${info.ttl} (Linux/iOS/Android range) → +10 to Server, Mobile, and Router each — weak differentiator since all three gain equally`);
    } else {
      fired.push(`TTL ${info.ttl} — outside standard OS ranges, no weight applied`);
    }
  } else {
    missing.push('No TTL observed — would add +30 to Laptop/Desktop (TTL 128) or Router (TTL 255)');
  }

  // ── App traffic profile ─────────────────────────────────────────────────
  const apps = info.apps ?? [];
  if (apps.length > 0) {
    const mobileHits = apps.filter(a => matchesAny(a, MOBILE_APPS));
    const serverHits = apps.filter(a => matchesAny(a, SERVER_APPS));
    const laptopHits = apps.filter(a => matchesAny(a, LAPTOP_APPS));
    const routerHits = apps.filter(a => matchesAny(a, ROUTER_APPS));

    if (mobileHits.length > 0)
      fired.push(`Mobile apps (${mobileHits.slice(0, 3).join(', ')}${mobileHits.length > 3 ? '…' : ''}) → +${mobileHits.length * 20} to Mobile`);
    if (serverHits.length > 0)
      fired.push(`Server-side apps (${serverHits.slice(0, 3).join(', ')}${serverHits.length > 3 ? '…' : ''}) → +${serverHits.length * 20} to Server`);
    if (laptopHits.length > 0)
      fired.push(`Productivity/conferencing apps (${laptopHits.slice(0, 3).join(', ')}${laptopHits.length > 3 ? '…' : ''}) → +${laptopHits.length * 20} to Laptop/Desktop`);
    if (routerHits.length > 0)
      fired.push(`Routing/management apps (${routerHits.slice(0, 3).join(', ')}${routerHits.length > 3 ? '…' : ''}) → +${routerHits.length * 20} to Router`);
    if (mobileHits.length === 0 && serverHits.length === 0 && laptopHits.length === 0 && routerHits.length === 0)
      fired.push(`${apps.length} app(s) observed — none matched a scored category, no weight applied`);
  } else {
    missing.push('No application traffic observed — each matched app adds +20 to its category (mobile, server, laptop, or router)');
  }

  // ── Peer count heuristic ────────────────────────────────────────────────
  if (info.peerCount != null) {
    if (info.peerCount >= 20) {
      fired.push(`${info.peerCount} distinct peers (high fan-out) → +35 to Router`);
    } else if (info.peerCount >= 10) {
      fired.push(`${info.peerCount} distinct peers (moderate fan-out) → +15 to Router`);
    } else {
      fired.push(`${info.peerCount} distinct peers (low fan-out) — no fan-out weight applied`);
    }
  } else if (apps.length === 0) {
    missing.push('Peer count unknown — high fan-out (20+ peers) would add +35 to Router');
  }

  // ── Initiation ratio ────────────────────────────────────────────────────
  if (info.initiatedCount != null && info.conversationCount != null && info.conversationCount > 0) {
    const ratio = info.initiatedCount / info.conversationCount;
    if (ratio < 0.2) {
      fired.push(`${Math.round(ratio * 100)}% outbound-initiated — mostly inbound → +35 to Server`);
    } else if (ratio <= 0.5) {
      fired.push(`${Math.round(ratio * 100)}% outbound-initiated — more inbound than outbound → +15 to Server`);
    } else {
      fired.push(`${Math.round(ratio * 100)}% outbound-initiated — client-like pattern, no server weight applied`);
    }
  } else if (info.conversationCount == null || info.conversationCount === 0) {
    missing.push('Connection direction unknown — mostly-inbound traffic would add +35 to Server');
  }

  // ── Suggestions when confidence is low ─────────────────────────────────
  if (info.confidence < 50) {
    if (!info.manufacturer) {
      missing.push('Confidence is low — resolving the MAC OUI (+40) would be the biggest single improvement');
    }
    if (apps.length < 3) {
      missing.push('Confidence is low — more varied traffic would expose additional app signals (+20 each)');
    }
  }

  return { fired, missing };
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
};

/**
 * Returns the Bootstrap Icon class name for the device type.
 */
export function deviceTypeIcon(deviceType: DeviceType): string {
  return DEVICE_TYPE_ICONS[deviceType] ?? 'bi-question-circle';
}

/** All canonical device type values shown in filter UIs. */
export const DEVICE_TYPES: DeviceType[] = [
  'ROUTER',
  'MOBILE',
  'LAPTOP_DESKTOP',
  'SERVER',
  'IOT',
  'DNS_SERVER',
  'WEB_SERVER',
  'API_SERVER',
  'UNKNOWN',
];
