import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';

/** The three per-network address lists (#915 phase 4). */
export type AddressKind = 'subnets' | 'custom-private-ranges' | 'ip-org-rules';

/**
 * One row of a network's view: the network's own entry (`scope: 'network'`, possibly hiding or
 * overriding the default's) or the default's (`scope: 'default'`).
 */
export interface AddressEntry {
  id: number;
  cidr: string;
  /** Subnets and IP-org rules. */
  label?: string | null;
  /** Subnets. */
  description?: string | null;
  /** Private/public ranges: PRIVATE or PUBLIC. */
  classification?: 'PRIVATE' | 'PUBLIC' | null;
  scope: 'default' | 'network';
  hidden: boolean;
  overridesDefault: boolean;
}

export interface AddressEntryInput {
  cidr: string;
  label?: string | null;
  description?: string | null;
  classification?: 'PRIVATE' | 'PUBLIC';
  hidden?: boolean;
}

export const networkAddressService = {
  list: async (networkId: string, kind: AddressKind): Promise<AddressEntry[]> =>
    (await apiClient.get<AddressEntry[]>(API_ENDPOINTS.NETWORK_ADDRESS_ENTRIES(networkId, kind))).data,

  /** Override or add the network's entry for a CIDR, or hide the default's (`hidden: true`). */
  put: async (networkId: string, kind: AddressKind, body: AddressEntryInput): Promise<AddressEntry> => {
    // A subnet label set here is the analyst's, so it counts as confirmed (and baselines staleness).
    const payload = kind === 'subnets' ? { ...body, confirmed: !body.hidden, networkId } : body;
    return (await apiClient.post<AddressEntry>(API_ENDPOINTS.NETWORK_ADDRESS_ENTRIES(networkId, kind), payload)).data;
  },

  /** Removes the network's entry, so the default applies again. */
  revert: async (networkId: string, kind: AddressKind, id: number): Promise<void> => {
    await apiClient.delete(API_ENDPOINTS.NETWORK_ADDRESS_ENTRY(networkId, kind, id));
  },

  /** The entries in effect: the network's visible ones and the default's it leaves alone. */
  visible: (entries: AddressEntry[]): AddressEntry[] => entries.filter(e => !e.hidden),
};
