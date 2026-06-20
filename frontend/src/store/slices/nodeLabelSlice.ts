import type { StateCreator } from 'zustand';

/** A field on a host that can be shown as a line of text below its graph node. */
export type NodeLabelField = 'ip' | 'hostname' | 'mac' | 'deviceType' | 'manufacturer';

/** Human-readable name for each selectable field (shown in the settings modal). */
export const NODE_LABEL_FIELD_META: Record<NodeLabelField, { label: string; icon: string }> = {
  ip: { label: 'IP address', icon: 'bi-hdd-network' },
  hostname: { label: 'Hostname', icon: 'bi-tag' },
  mac: { label: 'MAC address', icon: 'bi-ethernet' },
  deviceType: { label: 'Device type', icon: 'bi-pc-display' },
  manufacturer: { label: 'Manufacturer', icon: 'bi-building' },
};

/** One field together with whether it is currently shown. Order matters: it is the draw order. */
export interface NodeLabelFieldOption {
  field: NodeLabelField;
  enabled: boolean;
}

export interface NodeLabelConfig {
  /** Ordered list of every field with its enabled flag; enabled ones render top-to-bottom. */
  fields: NodeLabelFieldOption[];
  /** Optional static text drawn as the final line under every node. */
  customText: string;
}

export const DEFAULT_NODE_LABEL_CONFIG: NodeLabelConfig = {
  fields: [
    { field: 'hostname', enabled: true },
    { field: 'ip', enabled: true },
    { field: 'mac', enabled: false },
    { field: 'deviceType', enabled: false },
    { field: 'manufacturer', enabled: false },
  ],
  customText: '',
};

export interface NodeLabelSlice {
  nodeLabelConfig: NodeLabelConfig;
  setNodeLabelConfig: (config: NodeLabelConfig) => void;
  resetNodeLabelConfig: () => void;
}

export const createNodeLabelSlice: StateCreator<NodeLabelSlice> = set => ({
  nodeLabelConfig: DEFAULT_NODE_LABEL_CONFIG,
  setNodeLabelConfig: config => set({ nodeLabelConfig: config }),
  resetNodeLabelConfig: () => set({ nodeLabelConfig: DEFAULT_NODE_LABEL_CONFIG }),
});
