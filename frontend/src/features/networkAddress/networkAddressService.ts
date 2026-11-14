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
  /** On a subnet: which of several networks sharing the range it's for (#462). */
  segmentKey?: string | null;
  segmentLabel?: string | null;
}

const NETWORK_LIST: Record<AddressKind, (networkId: string) => string> = {
  subnets: API_ENDPOINTS.NETWORK_SUBNETS,
  'custom-private-ranges': API_ENDPOINTS.NETWORK_PRIVATE_RANGES,
  'ip-org-rules': API_ENDPOINTS.NETWORK_ORG_RULES,
};
const NETWORK_ENTRY: Record<AddressKind, (networkId: string, id: number) => string> = {
  subnets: API_ENDPOINTS.NETWORK_SUBNET,
  'custom-private-ranges': API_ENDPOINTS.NETWORK_PRIVATE_RANGE,
  'ip-org-rules': API_ENDPOINTS.NETWORK_ORG_RULE,
};

export const networkAddressService = {
  list: async (networkId: string, kind: AddressKind): Promise<AddressEntry[]> =>
    (await apiClient.get<AddressEntry[]>(NETWORK_LIST[kind](networkId))).data,

  /** Override or add the network's entry for a CIDR, or hide the default's (`hidden: true`). */
  put: async (networkId: string, kind: AddressKind, body: AddressEntryInput): Promise<AddressEntry> => {
    // A subnet label set here is the analyst's, so it counts as confirmed (and baselines staleness).
    const payload = kind === 'subnets' ? { ...body, confirmed: !body.hidden, networkId } : body;
    return (await apiClient.post<AddressEntry>(NETWORK_LIST[kind](networkId), payload)).data;
  },

  /** Removes the network's entry, so the default applies again. */
  revert: async (networkId: string, kind: AddressKind, id: number): Promise<void> => {
    await apiClient.delete(NETWORK_ENTRY[kind](networkId, id));
  },

  /** The entries in effect: the network's visible ones and the default's it leaves alone. */
  visible: (entries: AddressEntry[]): AddressEntry[] => entries.filter(e => !e.hidden),
};

/**
 * Where an address list reads and writes: a network's own layer (#915 phase 4), or the shared
 * default every network starts from (edited in the System console).
 */
export interface AddressSource {
  mode: 'network' | 'default';
  /** The permission that gates changes. */
  permission: 'NETWORK_SETTINGS' | 'ADDRESS_DEFAULTS';
  list(kind: AddressKind): Promise<AddressEntry[]>;
  /** Network: override, add or hide. Default: set the CIDR's entry. */
  put(kind: AddressKind, input: AddressEntryInput): Promise<unknown>;
  /** Network: revert to the default. Default: delete. */
  remove(kind: AddressKind, entry: AddressEntry): Promise<void>;
}

export function networkSource(networkId: string): AddressSource {
  return {
    mode: 'network',
    permission: 'NETWORK_SETTINGS',
    list: kind => networkAddressService.list(networkId, kind),
    put: (kind, input) => networkAddressService.put(networkId, kind, input),
    remove: (kind, entry) => networkAddressService.revert(networkId, kind, entry.id),
  };
}

const DEFAULT_PATHS: Record<AddressKind, string> = {
  subnets: '/subnets',
  'custom-private-ranges': '/custom-private-ranges',
  'ip-org-rules': '/ip-org-rules',
};

/** The shared default (#915 phase 4c). Every row is the default's own. */
export const defaultSource: AddressSource = {
  mode: 'default',
  permission: 'ADDRESS_DEFAULTS',
  list: async kind => {
    const rows = (await apiClient.get<AddressEntry[]>(DEFAULT_PATHS[kind])).data;
    return rows.map(r => ({ ...r, scope: 'default' as const, hidden: false, overridesDefault: false }));
  },
  put: async (kind, input) => {
    const body = kind === 'subnets' ? { ...input, confirmed: true } : input;
    return (await apiClient.post(DEFAULT_PATHS[kind], body)).data;
  },
  remove: async (kind, entry) => {
    await apiClient.delete(`${DEFAULT_PATHS[kind]}/${entry.id}`);
  },
};
