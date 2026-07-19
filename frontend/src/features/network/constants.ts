import type { NodeType } from './types';

/**
 * Single source of truth for protocol edge colors and display labels used in
 * NetworkGraph (edge strokes) and NetworkControls (legend).
 *
 * This is a *curated* palette, not a hash: well-known protocols get a hand-picked
 * colour; everything else falls back to DEFAULT_EDGE_COLOR (grey) and collapses
 * into one "Other" legend entry. Adding a protocol here makes it appear in the
 * legend automatically. Each entry needs a UNIQUE colour, or the legend (which
 * groups by colour) would hide one behind the other — the only deliberate
 * exceptions are aliases that share a swatch on purpose (HTTPS/TLS).
 *
 * Version-suffixed names (TLSv1.2, SSHv2, IGMPv3, …) do NOT need their own entry:
 * normalizeProtocol() strips the suffix and folds them into the base protocol.
 * Only irregular/compound variant names go in PROTOCOL_ALIASES below.
 *
 * Distinguishing this many colours by eye has limits; the legend is the decoder.
 * Keys are UPPERCASE (protocol names are matched case-insensitively).
 */
export const PROTOCOL_COLORS: Record<string, string> = {
  // Web / transport-security
  HTTP: '#2ecc71',
  HTTPS: '#3498db',
  TLS: '#3498db',
  QUIC: '#6c5ce7',
  // Name resolution / discovery
  DNS: '#f39c12',
  MDNS: '#c0ca33',
  SSDP: '#00897b',
  // Core transport / net-layer
  TCP: '#7f8c8d',
  UDP: '#f1c40f',
  ICMP: '#e67e22',
  ICMPV6: '#e67e22',
  IGMP: '#af7ac5',
  ARP: '#16a085',
  // Mail (pink/magenta family)
  SMTP: '#e84393',
  POP: '#d81b60',
  IMAP: '#ad1457',
  // Remote access / file transfer
  SSH: '#17a2b8',
  TELNET: '#7d6608',
  FTP: '#a04000',
  TFTP: '#a1887f',
  SMB: '#2471a3',
  RDP: '#7b1fa2',
  // Infra services
  DHCP: '#229954',
  NTP: '#5c6bc0',
  SNMP: '#0e7c86',
  LDAP: '#303f9f',
  SYSLOG: '#546e7a',
  // Voice
  SIP: '#b9770e',
  RTP: '#ff7043',
  // L2 control
  STP: '#8e44ad',
  RSTP: '#8e44ad',
  LLDP: '#6c3483',
  CDP: '#5b2c6f',
  EAPOL: '#c0392b',
  LACP: '#1a5276',
};

export const DEFAULT_EDGE_COLOR = '#95a5a6';

/**
 * Irregular variant / compound protocol names that should fold into a base
 * protocol above but don't follow the "base + version suffix" pattern that
 * normalizeProtocol() strips automatically. Keep this small — most variants
 * (TLSv1.2, SSHv2, …) need no entry.
 */
export const PROTOCOL_ALIASES: Record<string, string> = {
  SSL: 'TLS',
  'HTTP/XML': 'HTTP',
  'FTP-DATA': 'FTP',
  'SIP/SDP': 'SIP',
  'SMTP/IMF': 'SMTP',
  'POP/IMF': 'POP',
};

/**
 * Canonical protocol key for a raw tshark protocol name, used for both colour
 * and legend grouping. Resolution order:
 *   1. exact match in PROTOCOL_COLORS  (keeps distinct entries like ICMPv6, RSTP)
 *   2. explicit alias in PROTOCOL_ALIASES
 *   3. strip a trailing version suffix (V2, v1.2, " 2") and retry the base
 *   4. otherwise the uppercased name itself (an unmapped protocol)
 *
 * Tolerates missing/malformed values (null/undefined/non-string) by returning '',
 * which resolves to DEFAULT_EDGE_COLOR / the "Other" legend bucket — an edge with
 * no protocol must never crash the whole graph render.
 */
export function normalizeProtocol(protocol: string | null | undefined): string {
  if (typeof protocol !== 'string' || protocol === '') return '';
  const upper = protocol.toUpperCase();
  if (upper in PROTOCOL_COLORS) return upper;
  if (upper in PROTOCOL_ALIASES) return PROTOCOL_ALIASES[upper];
  // Fold "<base><version>" (TLSV1.2, SSHV2, IGMPV3, SMB2, RDPUDP2, PCP V2, …) into
  // <base>. Requires the base to end in a letter so pure-numeric names like
  // "802.11" or raw ethertypes ("0X5E00") are left untouched.
  const base = upper.replace(/\s*V?\d+(?:\.\d+)*$/, '');
  if (base && base !== upper && base in PROTOCOL_COLORS) return base;
  return upper;
}

export function getProtocolColor(protocol: string): string {
  return PROTOCOL_COLORS[normalizeProtocol(protocol)] ?? DEFAULT_EDGE_COLOR;
}

/**
 * Display label overrides for edge protocol legend entries.
 * Keys not listed here use the key itself as the label.
 */
export const PROTOCOL_LABELS: Record<string, string> = {
  HTTPS: 'HTTPS/TLS',
  STP: 'STP/RSTP',
  ICMPV6: 'ICMPv6',
};

/**
 * Builds the edge-colour legend entries for the protocols actually present in a
 * graph, so the NetworkGraph overlay legend explains its coloured strokes.
 *
 * - Ordering follows PROTOCOL_COLORS definition order (the source of truth), so
 *   adding a protocol there makes it appear with no other change.
 * - Protocols sharing a colour collapse into a single swatch (e.g. HTTPS + TLS
 *   → one `#3498db` entry). The label comes from the first present protocol of
 *   that colour, via PROTOCOL_LABELS (so HTTPS → "HTTPS/TLS").
 * - `hasUnmapped` is true when any present protocol falls back to
 *   DEFAULT_EDGE_COLOR, so callers can explain the grey strokes.
 *
 * Mirrors getProtocolColor(), so the legend stays in sync with the strokes.
 */
export function buildProtocolLegend(
  protocols: Iterable<string>,
): { entries: Array<{ color: string; label: string }>; hasUnmapped: boolean } {
  const present = new Set<string>();
  let hasUnmapped = false;
  for (const p of protocols) {
    // Normalize first so variants (TLSv1.2, SSHv2, SSL, …) fold into their base
    // entry instead of counting as unmapped.
    const key = normalizeProtocol(p);
    if (key in PROTOCOL_COLORS) present.add(key);
    else hasUnmapped = true;
  }

  const entries: Array<{ color: string; label: string }> = [];
  const seenColors = new Set<string>();
  for (const [key, color] of Object.entries(PROTOCOL_COLORS)) {
    if (!present.has(key) || seenColors.has(color)) continue;
    seenColors.add(color);
    entries.push({ color, label: PROTOCOL_LABELS[key] ?? key });
  }
  return { entries, hasUnmapped };
}

/**
 * Single source of truth for all per-node-type display properties.
 * Adding a new NodeType requires only one change here.
 */
export const NODE_TYPE_CONFIG: Record<NodeType, {
  label: string;
  icon: string;
  badgeClass: string;
  color: string;
}> = {
  'dns-server':      { label: 'DNS Server',       icon: 'bi-globe2',          badgeClass: 'bg-warning text-dark', color: '#f39c12' },
  'web-server':      { label: 'Web Server',        icon: 'bi-server',          badgeClass: 'bg-success',           color: '#2ecc71' },
  'ssh-server':      { label: 'SSH Server',        icon: 'bi-terminal',        badgeClass: 'bg-info text-dark',    color: '#1abc9c' },
  'ftp-server':      { label: 'FTP Server',        icon: 'bi-folder-symlink',  badgeClass: 'bg-secondary',         color: '#16a085' },
  'mail-server':     { label: 'Mail Server',       icon: 'bi-envelope',        badgeClass: 'bg-danger',            color: '#e91e63' },
  'dhcp-server':     { label: 'DHCP Server',       icon: 'bi-broadcast',       badgeClass: 'bg-secondary',         color: '#8e44ad' },
  'ntp-server':      { label: 'NTP Server',        icon: 'bi-clock',           badgeClass: 'bg-dark',              color: '#6c3483' },
  'database-server': { label: 'Database Server',   icon: 'bi-database',        badgeClass: 'bg-danger',            color: '#e67e22' },
  router:            { label: 'Router / Gateway',  icon: 'bi-router',          badgeClass: 'bg-warning text-dark', color: '#d4ac0d' },
  client:            { label: 'Client',            icon: 'bi-laptop',          badgeClass: 'bg-primary',           color: '#3498db' },
  'l2-device':       { label: 'L2 Device',         icon: 'bi-ethernet',        badgeClass: 'bg-teal text-white',   color: '#1abc9c' },
  unknown:           { label: 'Unknown',           icon: 'bi-question-circle', badgeClass: 'bg-light text-dark',   color: '#95a5a6' },
};

/** @deprecated Use NODE_TYPE_CONFIG[type].label instead. */
export const NODE_TYPE_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(NODE_TYPE_CONFIG).map(([k, v]) => [k, v.label])
);

/**
 * Converts a raw activeNodeFilters key (e.g. "nt:router", "dt:IOT") to a
 * human-readable label using the existing display maps.
 */
export function nodeFilterLabel(key: string): string {
  if (key.startsWith('nt:')) {
    const type = key.slice(3);
    return NODE_TYPE_LABELS[type] ?? type.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  }
  if (key.startsWith('dt:')) {
    // Inline the deviceTypeLabel logic to avoid a circular import.
    const dt = key.slice(3);
    switch (dt) {
      case 'ROUTER': return 'Router';
      case 'MOBILE': return 'Mobile';
      case 'LAPTOP_DESKTOP': return 'Laptop / Desktop';
      case 'SERVER': return 'Server';
      case 'IOT': return 'IoT Device';
      case 'UNKNOWN': return 'Unknown';
      default: return dt;
    }
  }
  return key;
}

/**
 * Returns a toggle callback that adds/removes a value from a string-array state.
 * Used in network diagram filter panels to toggle protocol/node/app filters.
 */
export function toggleSet(setter: React.Dispatch<React.SetStateAction<string[]>>) {
  return (val: string) =>
    setter(prev => (prev.includes(val) ? prev.filter(v => v !== val) : [...prev, val]));
}

/**
 * Builds the list of human-readable active-filter labels from a filter state
 * snapshot. Used in both NetworkDiagramPage (ref sync) and AnalysisPage (PDF
 * report). Centralised here so the two sites stay in sync automatically.
 */
const GHOST_FLAG_LABELS: Record<string, string> = {
  'no-response':      'No response',
  'arp-no-reply':     'ARP no-reply',
  'icmp-unreachable': 'ICMP unreachable',
  'ttl-exceeded':     'TTL exceeded',
};

export function buildActiveFilterLabels(filters: {
  ipFilter: string;
  portFilter: string;
  hasRisksOnly: boolean;
  activeLegendProtocols: string[];
  activeNodeFilters: string[];
  activeAppFilters: string[];
  activeL7Protocols: string[];
  activeCategories: string[];
  activeRiskTypes: string[];
  activeCustomSigs: string[];
  activeFileTypes: string[];
  activeCountries: string[];
  activeGhostFilters?: string[];
}): string[] {
  const labels: string[] = [];
  if (filters.ipFilter) labels.push(`IP: ${filters.ipFilter}`);
  if (filters.portFilter) labels.push(`Port: ${filters.portFilter}`);
  if (filters.hasRisksOnly) labels.push('Has Risks: Yes');
  if (filters.activeLegendProtocols.length > 0)
    labels.push(`Protocol: ${filters.activeLegendProtocols.join(', ')}`);
  if (filters.activeNodeFilters.length > 0)
    labels.push(`Node type: ${filters.activeNodeFilters.map(nodeFilterLabel).join(', ')}`);
  if (filters.activeAppFilters.length > 0)
    labels.push(`App: ${filters.activeAppFilters.join(', ')}`);
  if (filters.activeL7Protocols.length > 0)
    labels.push(`L7: ${filters.activeL7Protocols.join(', ')}`);
  if (filters.activeCategories.length > 0)
    labels.push(`Category: ${filters.activeCategories.join(', ')}`);
  if (filters.activeRiskTypes.length > 0)
    labels.push(`Risk type: ${filters.activeRiskTypes.join(', ')}`);
  if (filters.activeCustomSigs.length > 0)
    labels.push(`Custom signature: ${filters.activeCustomSigs.join(', ')}`);
  if (filters.activeFileTypes.length > 0)
    labels.push(`File type: ${filters.activeFileTypes.join(', ')}`);
  if (filters.activeCountries.length > 0)
    labels.push(`Country: ${filters.activeCountries.join(', ')}`);
  if (filters.activeGhostFilters && filters.activeGhostFilters.length > 0)
    labels.push(
      `Hide ghost: ${filters.activeGhostFilters.map(f => GHOST_FLAG_LABELS[f] ?? f).join(', ')}`
    );
  return labels;
}

/** @deprecated Use NODE_TYPE_CONFIG[type].color instead. */
export const NODE_TYPE_COLORS: Record<string, string> = Object.fromEntries(
  Object.entries(NODE_TYPE_CONFIG).map(([k, v]) => [k, v.color])
);
