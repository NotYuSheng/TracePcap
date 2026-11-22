import { useEffect, useState } from 'react';

/** One protocol nDPI can detect, with a plain-English explanation (from the old reference page). */
export interface NdpiProtocol {
  id: number;
  /** nDPI's name, e.g. "TLS", "FTP_CONTROL", "Discord". */
  name: string;
  category: string;
  title: string;
  description: string;
  /** How nDPI recognises it: by port, deep inspection, the TLS handshake, hostname, heuristics or IP. */
  detection: { type: string; label: string }[];
  references: { label: string; url: string }[];
  note?: string;
}

export const CATEGORY_LABELS: Record<string, string> = {
  network: 'Network',
  web: 'Web',
  email: 'Email',
  social: 'Social',
  streaming: 'Streaming',
  cloud: 'Cloud',
  vpn: 'VPN',
  gaming: 'Gaming',
  database: 'Database',
  industrial: 'Industrial',
  messaging: 'Messaging',
  remote: 'Remote access',
  iot: 'IoT',
  crypto: 'Crypto',
  other: 'Other',
};

export const DETECTION_LABELS: Record<string, string> = {
  port: 'Port',
  deep: 'Deep inspection',
  tls: 'TLS handshake',
  host: 'Hostname',
  heur: 'Heuristic',
  ip: 'IP address',
};

// The data is ~200 KB, so it's its own chunk, loaded the first time something asks for it.
let cache: Promise<NdpiProtocol[]> | null = null;

export function loadNdpiProtocols(): Promise<NdpiProtocol[]> {
  if (!cache) {
    cache = import('./protocols.json').then(m => m.default as NdpiProtocol[]);
    cache.catch(() => {
      cache = null;
    });
  }
  return cache;
}

/** Every protocol in the reference, or null while it loads (or when {@code enabled} is false). */
export function useNdpiProtocols(enabled = true): NdpiProtocol[] | null {
  const [protocols, setProtocols] = useState<NdpiProtocol[] | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    loadNdpiProtocols()
      .then(p => active && setProtocols(p))
      .catch(() => active && setProtocols(null));
    return () => {
      active = false;
    };
  }, [enabled]);
  return protocols;
}

/**
 * The reference entry for a name the analysis shows, ignoring case. nDPI's layered names
 * ("TLS.Discord", "QUIC.Google") match their most specific part first, then the transport.
 */
export function findNdpiProtocol(protocols: NdpiProtocol[], name: string): NdpiProtocol | undefined {
  const byName = (n: string) => protocols.find(p => p.name.toLowerCase() === n.trim().toLowerCase());
  const parts = name.split('.');
  return byName(name) ?? byName(parts[parts.length - 1]) ?? byName(parts[0]);
}

/** Where a protocol's reference entry opens in the app. */
export function protocolReferenceUrl(name?: string): string {
  return name ? `/reference/protocols?protocol=${encodeURIComponent(name)}` : '/reference/protocols';
}
