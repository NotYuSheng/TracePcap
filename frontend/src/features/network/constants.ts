/**
 * Single source of truth for protocol edge colors and display labels used in
 * NetworkGraph (edge strokes) and NetworkControls (legend).
 *
 * To add a new protocol: add an entry here. The legend renders automatically.
 */
export const PROTOCOL_COLORS: Record<string, string> = {
  HTTP: '#2ecc71',
  HTTPS: '#3498db',
  TLS: '#3498db',
  DNS: '#f39c12',
  TCP: '#7f8c8d',
  UDP: '#f1c40f',
  ICMP: '#e67e22',
  ICMPV6: '#e67e22',
  ARP: '#16a085',
  STP: '#8e44ad',
  RSTP: '#8e44ad',
  LLDP: '#6c3483',
  CDP: '#5b2c6f',
  EAPOL: '#c0392b',
  LACP: '#1a5276',
};

export const DEFAULT_EDGE_COLOR = '#95a5a6';

export function getProtocolColor(protocol: string): string {
  return PROTOCOL_COLORS[protocol.toUpperCase()] ?? DEFAULT_EDGE_COLOR;
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
 * Display label overrides for node type legend entries.
 * Keys not listed here are title-cased automatically.
 */
export const NODE_TYPE_LABELS: Record<string, string> = {
  'dns-server': 'DNS Server',
  'web-server': 'Web Server',
  'ssh-server': 'SSH Server',
  'ftp-server': 'FTP Server',
  'mail-server': 'Mail Server',
  'dhcp-server': 'DHCP Server',
  'ntp-server': 'NTP Server',
  'database-server': 'Database Server',
  router: 'Router / Gateway',
  client: 'Client',
  'l2-device': 'L2 Device',
  anomaly: 'Anomaly',
  unknown: 'Unknown',
};

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
  return labels;
}

/**
 * Single source of truth for node type colors used in
 * NetworkGraph (node fill) and NetworkControls (legend).
 */
export const NODE_TYPE_COLORS: Record<string, string> = {
  'dns-server': '#f39c12',
  'web-server': '#2ecc71',
  'ssh-server': '#1abc9c',
  'ftp-server': '#16a085',
  'mail-server': '#e91e63',
  'dhcp-server': '#8e44ad',
  'ntp-server': '#6c3483',
  'database-server': '#e67e22',
  router: '#d4ac0d',
  client: '#3498db',
  'l2-device': '#1abc9c',
  anomaly: '#e74c3c',
  unknown: '#95a5a6',
};
