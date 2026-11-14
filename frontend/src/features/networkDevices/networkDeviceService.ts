import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { PaginatedResponse } from '@/types';

/** Mirrors NetworkDeviceDto (#918 slice 4). */
export interface NetworkDevice {
  /** The MAC it was last seen with. */
  mac: string;
  /** Every MAC it was seen with: more than one when linked as one device. */
  macs: string[];
  name?: string | null;
  deviceType?: string | null;
  vendor?: string | null;
  macKind: 'HARDWARE' | 'PRIVATE' | 'VIRTUAL_MACHINE' | 'CONTAINER';
  label?: string | null;
  addresses: { ip: string; firstSnapshot: number; lastSnapshot: number }[];
  seenInFileIds: string[];
  lastFileId?: string | null;
  lastKey?: string | null;
  flags: { kind: string; severity: 'high' | 'medium' | 'info'; text: string }[];
  links: DeviceLink[];
}

/** An analyst's decision that two MACs are one device (same) or not (not_same). */
export interface DeviceLink {
  id: number;
  macA: string;
  macB: string;
  decision: 'same' | 'not_same';
  reason: string;
  actor?: string | null;
  createdAt?: string | number[] | null;
}

/** Two private MACs that look like one device (#918 slice 4b). */
export interface DeviceLinkSuggestion {
  macA: string;
  nameA?: string | null;
  firstSnapshotA: number;
  lastSnapshotA: number;
  macB: string;
  nameB?: string | null;
  firstSnapshotB: number;
  lastSnapshotB: number;
  evidence: { strength: 'strong' | 'medium' | 'weak'; what: string; detail: string }[];
}

export interface NetworkDeviceCounts {
  all: number;
  irregular: number;
  privateMac: number;
}

export type DeviceShow = 'all' | 'irregular' | 'private';

export const networkDeviceService = {
  list: async (
    networkId: string,
    opts: { q?: string; show?: DeviceShow; page: number; pageSize: number },
  ): Promise<PaginatedResponse<NetworkDevice>> =>
    (
      await apiClient.get<PaginatedResponse<NetworkDevice>>(API_ENDPOINTS.NETWORK_DEVICES(networkId), {
        params: {
          q: opts.q || undefined,
          show: opts.show && opts.show !== 'all' ? opts.show : undefined,
          page: opts.page,
          pageSize: opts.pageSize,
        },
      })
    ).data,

  suggestions: async (networkId: string): Promise<DeviceLinkSuggestion[]> =>
    (await apiClient.get<DeviceLinkSuggestion[]>(API_ENDPOINTS.NETWORK_DEVICE_LINK_SUGGESTIONS(networkId))).data,

  decide: async (
    networkId: string,
    body: { macA: string; macB: string; decision: 'same' | 'not_same'; reason: string },
  ): Promise<DeviceLink> =>
    (await apiClient.post<DeviceLink>(API_ENDPOINTS.NETWORK_DEVICE_LINKS(networkId), body)).data,

  undo: async (networkId: string, linkId: number): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.NETWORK_DEVICE_LINK(networkId, linkId));
  },

  counts: async (networkId: string): Promise<NetworkDeviceCounts> =>
    (await apiClient.get<NetworkDeviceCounts>(API_ENDPOINTS.NETWORK_DEVICE_COUNTS(networkId))).data,
};
