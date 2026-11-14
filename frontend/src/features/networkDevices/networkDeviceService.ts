import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { PaginatedResponse } from '@/types';

/** Mirrors NetworkDeviceDto (#918 slice 4). */
export interface NetworkDevice {
  mac: string;
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

  counts: async (networkId: string): Promise<NetworkDeviceCounts> =>
    (await apiClient.get<NetworkDeviceCounts>(API_ENDPOINTS.NETWORK_DEVICE_COUNTS(networkId))).data,
};
