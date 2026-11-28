import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** Mirrors NetworkSegmentsResponse.Segment (#462, IPv6 #1357). */
export interface NetworkSegment {
  key: string;
  label: string;
  vlanId?: number | null;
  serverMac?: string | null;
  serverIds: string[];
  routers: string[];
  domains: string[];
  leaseSeconds: number[];
  /** Its IPv4 range, from DHCPv4; none on an IPv6-only network. */
  cidr?: string | null;
  /** The IPv6 prefixes its routers advertised. */
  prefixes?: string[];
  /** The MACs of the IPv6 routers that advertised on it. */
  routerMacs?: string[];
  clients: { ip: string; mac: string; hostname?: string | null }[];
  /** Clients that asked for an address on this network (its VLAN) and got none. */
  unanswered?: UnansweredClient[];
}

/** A client that asked for an address and was never answered, known by its MAC. */
export interface UnansweredClient {
  mac: string;
  hostname?: string | null;
  vlanId?: number | null;
  requests: number;
}

export interface NetworkSegmentOverlap {
  cidr?: string | null;
  segmentKeys: string[];
  sharedAddresses: string[];
}

export interface NetworkSegments {
  segments: NetworkSegment[];
  overlaps: NetworkSegmentOverlap[];
  /** Unanswered clients no network could be found for (no VLAN, or one nothing leased on). */
  unanswered?: UnansweredClient[];
}

/** MAC → the name each unanswered client asked under (DHCP option 12), where it gave one. */
export function unansweredNames(r: NetworkSegments): Map<string, string> {
  const out = new Map<string, string>();
  const all = [...r.segments.flatMap(s => s.unanswered ?? []), ...(r.unanswered ?? [])];
  for (const c of all) if (c.hostname) out.set(c.mac.toLowerCase(), c.hostname);
  return out;
}

export const networkSegmentService = {
  get: async (fileId: string): Promise<NetworkSegments> =>
    (await apiClient.get<NetworkSegments>(API_ENDPOINTS.FILE_NETWORK_SEGMENTS(fileId))).data,
};
