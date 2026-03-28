/**
 * Single source of truth for protocol edge colors used in
 * NetworkGraph (edge strokes) and NetworkControls (legend).
 */
export const PROTOCOL_COLORS: Record<string, string> = {
  HTTP:  '#2ecc71',
  HTTPS: '#3498db',
  TLS:   '#3498db',
  DNS:   '#f39c12',
  TCP:   '#7f8c8d',
  UDP:   '#f1c40f',
  ICMP:  '#e67e22',
  ARP:   '#16a085',
};

export const DEFAULT_EDGE_COLOR = '#95a5a6';

/**
 * Single source of truth for node type colors used in
 * NetworkGraph (node fill) and NetworkControls (legend).
 */
export const NODE_TYPE_COLORS: Record<string, string> = {
  'dns-server':      '#f39c12',
  'web-server':      '#2ecc71',
  'ssh-server':      '#1abc9c',
  'ftp-server':      '#16a085',
  'mail-server':     '#e91e63',
  'dhcp-server':     '#8e44ad',
  'ntp-server':      '#6c3483',
  'database-server': '#e67e22',
  'router':          '#d4ac0d',
  'client':          '#3498db',
  'anomaly':         '#e74c3c',
  'unknown':         '#95a5a6',
};
