import { useEffect, useState } from 'react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

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
 * The analysis and the reference spell names differently: the analysis says "SMTP", "Outlook",
 * "AppleiCloud", the reference "MAIL_SMTP", "MS_OUTLOOK", "APPLE_ICLOUD". A key that ignores case,
 * punctuation and the MAIL_/MS_ prefixes matches them; these few still need naming by hand.
 */
const ALIASES: Record<string, string> = {
  teams: 'msteams',
  messagepack: 'msgpack',
  postgresql: 'postgres',
};

/** A name as a matching key: "MAIL_SMTP" and "SMTP" both become "smtp". */
export function protocolKey(name: string): string {
  const key = name.trim().toLowerCase().replace(/^(mail_|ms_)/, '').replace(/[^a-z0-9]/g, '');
  return ALIASES[key] ?? key;
}

/**
 * The reference entry for a name the analysis shows. nDPI's layered names ("TLS.Discord",
 * "QUIC.Google") match their most specific part first, then the transport.
 */
export function findNdpiProtocol(protocols: NdpiProtocol[], name: string): NdpiProtocol | undefined {
  const byKey = (n: string) => protocols.find(p => protocolKey(p.name) === protocolKey(n));
  const parts = name.split('.');
  return byKey(name) ?? byKey(parts[parts.length - 1]) ?? byKey(parts[0]);
}

/** Where a protocol's reference entry opens in the app. */
export function protocolReferenceUrl(name?: string): string {
  return name ? `/reference/protocols?protocol=${encodeURIComponent(name)}` : '/reference/protocols';
}

/** Mirrors ProtocolUsageDto: an nDPI app name as the analysis records it, and how much of it you have. */
export interface ProtocolUsage {
  appName: string;
  captures: number;
  conversations: number;
}

/** Mirrors ProtocolCaptureDto. */
export interface ProtocolCapture {
  fileId: string;
  fileName: string;
  conversations: number;
}

export const protocolUsageService = {
  usage: async (): Promise<ProtocolUsage[]> =>
    (await apiClient.get<ProtocolUsage[]>(API_ENDPOINTS.PROTOCOL_USAGE)).data,
  captures: async (appName: string, limit = 20): Promise<ProtocolCapture[]> =>
    (await apiClient.get<ProtocolCapture[]>(API_ENDPOINTS.PROTOCOL_USAGE_CAPTURES(appName), { params: { limit } }))
      .data,
};

/**
 * Usage per reference entry, keyed by the entry's nDPI name: the analysis's names folded onto the
 * reference's (several analysis names can land on one entry, so they're added up).
 */
export function usageByProtocol(
  protocols: NdpiProtocol[],
  usage: ProtocolUsage[]
): Map<string, { appNames: string[]; captures: number; conversations: number }> {
  const out = new Map<string, { appNames: string[]; captures: number; conversations: number }>();
  for (const u of usage) {
    const p = findNdpiProtocol(protocols, u.appName);
    if (!p) continue;
    const cur = out.get(p.name) ?? { appNames: [], captures: 0, conversations: 0 };
    cur.appNames.push(u.appName);
    cur.captures = Math.max(cur.captures, u.captures);
    cur.conversations += u.conversations;
    out.set(p.name, cur);
  }
  return out;
}

/** Your protocol usage, or null while it loads (or if it couldn't). */
export function useProtocolUsage(): ProtocolUsage[] | null {
  const [usage, setUsage] = useState<ProtocolUsage[] | null>(null);
  useEffect(() => {
    let active = true;
    protocolUsageService
      .usage()
      .then(u => active && setUsage(u))
      .catch(() => active && setUsage([]));
    return () => {
      active = false;
    };
  }, []);
  return usage;
}
