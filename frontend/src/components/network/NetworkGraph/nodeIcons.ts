// ---------------------------------------------------------------------------
// Bootstrap Icons — unicode codepoints for each node type
// Pre-rendered to data URLs so Sigma's WebGL renderer can display them.
//
// Kept in its own module, free of the `sigma` import, so it can be unit-tested without pulling
// in Sigma's WebGL dependency (importing it crashes under jsdom) — see
// __tests__/iconCodepoints.test.ts. These tables drifted from the class names they were copied
// from once already (#495: IoT drew a lightbulb, Mobile a patch-minus).
// ---------------------------------------------------------------------------

// Generic nodeTypes that carry no specific service information.
// For these, deviceType provides a more meaningful colour signal.
export const GENERIC_NODE_TYPES = new Set(['client', 'unknown']);

// Icons for specific service nodeTypes
export const NODE_TYPE_ICONS: Record<string, string> = {
  'dns-server':      '\uf3ef', // bi-globe2
  'web-server':      '\uf52c', // bi-server
  'ssh-server':      '\uf5c3', // bi-terminal
  'ftp-server':      '\uf3d5', // bi-folder-symlink
  'mail-server':     '\uf32f', // bi-envelope
  'dhcp-server':     '\uf1d6', // bi-broadcast
  'ntp-server':      '\uf293', // bi-clock
  'database-server': '\uf8c4', // bi-database
  router:            '\uf6ec', // bi-router
  'l2-device':       '\uf6d5', // bi-ethernet
  cluster:           '\uf2ee', // bi-diagram-3
};

// Icons for device types — used on generic (client/unknown) nodes.
// Must stay in sync with deviceTypeIcon()'s class names (used by the legend).
export const DEVICE_TYPE_ICONS: Record<string, string> = {
  ROUTER:         '\uf6ec', // bi-router
  MOBILE:         '\uf4e7', // bi-phone
  LAPTOP_DESKTOP: '\uf456', // bi-laptop
  SERVER:         '\uf52c', // bi-server
  IOT:            '\uf2d6', // bi-cpu
  DNS_SERVER:     '\uf40d', // bi-hdd-network
  WEB_SERVER:     '\uf3ee', // bi-globe
  API_SERVER:     '\uf411', // bi-hdd-stack
};

export const FALLBACK_ICON = '\uf505'; // bi-question-circle

export function getNodeIcon(nodeType: string, deviceType: string): string {
  if (!GENERIC_NODE_TYPES.has(nodeType)) {
    return NODE_TYPE_ICONS[nodeType] ?? FALLBACK_ICON;
  }
  return DEVICE_TYPE_ICONS[deviceType] ?? FALLBACK_ICON;
}
