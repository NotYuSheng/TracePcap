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

export const occupancyService = {
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
