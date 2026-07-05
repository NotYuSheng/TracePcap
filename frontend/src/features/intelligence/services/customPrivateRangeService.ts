import { apiClient } from '@/services/api/client';
import type { CustomPrivateRange, IpClassification } from '../types/customPrivateRange.types';

export const customPrivateRangeService = {
  async list(): Promise<CustomPrivateRange[]> {
    const res = await apiClient.get<CustomPrivateRange[]>('/custom-private-ranges');
    return res.data;
  },

  async create(
    cidr: string,
    classification: IpClassification = 'PRIVATE',
  ): Promise<CustomPrivateRange> {
    const res = await apiClient.post<CustomPrivateRange>('/custom-private-ranges', {
      cidr,
      classification,
    });
    return res.data;
  },

  async delete(id: number): Promise<void> {
    await apiClient.delete(`/custom-private-ranges/${id}`);
  },
};
