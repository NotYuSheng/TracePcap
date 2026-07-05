import { apiClient } from '@/services/api/client';
import { SUBNET_ENDPOINTS } from '@/services/api/endpoints';
import type {
  SubnetDefinition,
  SubnetLabelSuggestion,
  SubnetCompositionHistoryEntry,
  SubnetOverlapWarning,
} from '../types/subnet.types';

export const subnetService = {
  list: () =>
    apiClient.get<SubnetDefinition[]>(SUBNET_ENDPOINTS.SUBNETS).then(r => r.data),

  // networkId (optional) lets the backend capture the staleness baseline from that network's
  // latest snapshot when a label is confirmed.
  upsert: (cidr: string, label: string, description: string, confirmed: boolean, networkId?: string) =>
    apiClient
      .post<SubnetDefinition>(SUBNET_ENDPOINTS.SUBNETS, { cidr, label, description, confirmed, networkId })
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

  // Ask the AI to suggest a label + description from the subnet's member-node behaviour. Not
  // persisted — the caller fills the edit form with the result and saves it via upsert.
  suggestLabel: (id: number, networkId?: string, fileId?: string) =>
    apiClient
      .post<SubnetLabelSuggestion>(SUBNET_ENDPOINTS.SUBNET_SUGGEST_LABEL(id, networkId, fileId))
      .then(r => r.data),

  // Per-snapshot composition history for the subnet, for the Snapshot History table.
  history: (id: number, networkId: string) =>
    apiClient
      .get<SubnetCompositionHistoryEntry[]>(SUBNET_ENDPOINTS.SUBNET_HISTORY(id, networkId))
      .then(r => r.data),

  // Mark a stale label still-correct and re-baseline the composition.
  dismissStaleness: (id: number, networkId?: string) =>
    apiClient
      .post<SubnetDefinition>(SUBNET_ENDPOINTS.SUBNET_DISMISS_STALENESS(id, networkId))
      .then(r => r.data),

  // Subnets flagged as possible overlapping networks (gateway IP answered by >1 MAC).
  overlaps: (networkId: string) =>
    apiClient
      .get<SubnetOverlapWarning[]>(SUBNET_ENDPOINTS.SUBNET_OVERLAPS(networkId))
      .then(r => r.data),
};
