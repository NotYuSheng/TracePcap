import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import type { CustomPrivateRange, IpClassification } from '../types/customPrivateRange.types';

export const customPrivateRangeService = {
  async list(): Promise<CustomPrivateRange[]> {
    const res = await apiClient.get<CustomPrivateRange[]>(API_ENDPOINTS.CUSTOM_PRIVATE_RANGES);
    return res.data;
  },

  async create(
    cidr: string,
    classification: IpClassification = 'PRIVATE',
  ): Promise<CustomPrivateRange> {
    const res = await apiClient.post<CustomPrivateRange>(API_ENDPOINTS.CUSTOM_PRIVATE_RANGES, {
      cidr,
      classification,
    });
    return res.data;
  },

  async delete(id: number): Promise<void> {
    await apiClient.delete(API_ENDPOINTS.CUSTOM_PRIVATE_RANGE_DELETE(id));
  },
};
