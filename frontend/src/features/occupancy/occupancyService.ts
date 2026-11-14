import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** The API sends LocalDateTime as an array (or, for keys, an ISO string). */
export type ApiDateTime = string | number[];

/** Mirrors HostOccupancyResponse.Occupancy (#918 item 3). */
export interface Occupancy {
  idx: number;
  mac?: string | null;
  hostname?: string | null;
  startsAt?: ApiDateTime | null;
  endsAt?: ApiDateTime | null;
  /** arp, dhcp or manual; null for the first. */
  startSource?: 'arp' | 'dhcp' | 'manual' | null;
  startEvidence?: string | null;
  /** startsAt as an ISO string, sent back exactly when merging. */
  boundaryKey?: string | null;
  automatic: boolean;
  conversations: number;
  /** This device's own classification, from its stretch's traffic only (#918 slice 2). */
  classification?: OccupancyClassification | null;
  /** The device's key: the bare IP for the first, ip@start or ip~network for another. */
  key?: string | null;
  /** The network it was on, when the address is used on several that share its range (#462). */
  network?: string | null;
  /** That network's MACs: a conversation is this device's when its side's MAC is one of them. */
  networkMacs?: string[] | null;
}

/** Mirrors HostOccupancyResponse.Classification. */
export interface OccupancyClassification {
  deviceType: string;
  confidence?: number | null;
  winnerScore?: number | null;
  winnerReasons?: string | null;
  runnerUpType?: string | null;
  runnerUpScore?: number | null;
  runnerUpReasons?: string | null;
  manufacturer?: string | null;
  ttl?: number | null;
  loggedInUser?: string | null;
}

/** Mirrors HostOccupancyResponse.Address: an address and the devices that held it, in time order. */
export interface ReusedAddress {
  ip: string;
  occupancies: Occupancy[];
}

export interface OccupancyDecision {
  id: number;
  at: ApiDateTime;
  action: 'split' | 'merge';
  reason: string;
  actor?: string | null;
  createdAt?: ApiDateTime | null;
}

export interface OccupancySuggestion {
  at: ApiDateTime;
  key: string;
  kind: 'mac' | 'dhcp' | 'silence';
  description: string;
}

/** Mirrors HostOccupancyResponse. */
export interface HostOccupancy {
  ip: string;
  firstActivity?: ApiDateTime | null;
  lastActivity?: ApiDateTime | null;
  overlapping: boolean;
  virtualAddress: boolean;
  /** The networks this address was used on, when more than one shares its range (#462). */
  networks?: string[];
  occupancies: Occupancy[];
  decisions: OccupancyDecision[];
  suggestions: OccupancySuggestion[];
  canEdit: boolean;
  editReason?: string | null;
}

/** A LocalDateTime as the value of a datetime-local input with seconds (wall-clock, no zone). */
export function toInputValue(dt: ApiDateTime | null | undefined): string {
  if (!dt) return '';
  if (typeof dt === 'string') return dt.slice(0, 19);
  const [y, mo, d, h = 0, mi = 0, s = 0] = dt;
  const p = (n: number) => String(n).padStart(2, '0');
  return `${y}-${p(mo)}-${p(d)}T${p(h)}:${p(mi)}:${p(s)}`;
}

/** Mirrors DeviceMoveDto: the same MAC on one address, then another. */
export interface DeviceMove {
  mac: string;
  fromIp: string;
  fromKey: string;
  fromHostname?: string | null;
  left?: ApiDateTime | null;
  toIp: string;
  toKey: string;
  toHostname?: string | null;
  arrived: ApiDateTime;
  evidence: string;
}

export const occupancyService = {
  /** Devices that moved to another address in the capture. */
  moves: async (fileId: string): Promise<DeviceMove[]> =>
    (await apiClient.get<DeviceMove[]>(API_ENDPOINTS.FILE_DEVICE_MOVES(fileId))).data,

  /** Addresses that more than one device held in the capture; empty when none did. */
  listForFile: async (fileId: string): Promise<ReusedAddress[]> =>
    (await apiClient.get<ReusedAddress[]>(API_ENDPOINTS.FILE_OCCUPANCIES(fileId))).data,

  get: async (fileId: string, ip: string): Promise<HostOccupancy> =>
    (await apiClient.get<HostOccupancy>(API_ENDPOINTS.HOST_OCCUPANCIES(fileId, ip))).data,

  decide: async (
    fileId: string,
    ip: string,
    body: { at: string; action: 'split' | 'merge'; reason: string },
  ): Promise<HostOccupancy> =>
    (await apiClient.post<HostOccupancy>(API_ENDPOINTS.HOST_OCCUPANCY_DECISIONS(fileId, ip), body)).data,

  undo: async (fileId: string, ip: string, decisionId: number): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.HOST_OCCUPANCY_DECISION(fileId, ip, decisionId));
  },
};
