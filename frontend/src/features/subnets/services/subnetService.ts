import { apiClient } from '@/services/api/client';
import { SUBNET_ENDPOINTS } from '@/services/api/endpoints';
import type { SubnetDefinition } from '../types/subnet.types';

export const subnetService = {
  list: () =>
    apiClient.get<SubnetDefinition[]>(SUBNET_ENDPOINTS.SUBNETS).then(r => r.data),

  upsert: (cidr: string, label: string, description: string, confirmed: boolean) =>
    apiClient
      .post<SubnetDefinition>(SUBNET_ENDPOINTS.SUBNETS, { cidr, label, description, confirmed })
      .then(r => r.data),

  saveDetected: (cidr: string, label: string, description: string) =>
    apiClient
      .post<SubnetDefinition>(SUBNET_ENDPOINTS.SUBNET_SAVE_DETECTED, {
        cidr,
        label,
        description,
        confirmed: false,
      })
      .then(r => r.data),

  delete: (id: number) =>
    apiClient.delete(SUBNET_ENDPOINTS.SUBNET_DELETE(id)),

  detect: (fileId: string) =>
    apiClient
      .get<SubnetDefinition[]>(SUBNET_ENDPOINTS.SUBNET_DETECT(fileId))
      .then(r => r.data),

  detectFromNetwork: (networkId: string) =>
    apiClient
      .get<SubnetDefinition[]>(SUBNET_ENDPOINTS.SUBNET_DETECT_NETWORK(networkId))
      .then(r => r.data),
};
