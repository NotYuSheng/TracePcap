import type { StateCreator } from 'zustand';

/** A field on a host that can be shown as a line of text below its graph node. */
export type NodeLabelField = 'roleLabel' | 'ip' | 'hostname' | 'mac' | 'deviceType' | 'manufacturer';

/** Human-readable name for each selectable field (shown in the settings modal). */
export const NODE_LABEL_FIELD_META: Record<NodeLabelField, { label: string; icon: string }> = {
  roleLabel: { label: 'Role (analyst-assigned)', icon: 'bi-person-check' },
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
  /** Optional static text lines drawn as the final lines under every node (in order). */
  customText: string[];
}

export const DEFAULT_NODE_LABEL_CONFIG: NodeLabelConfig = {
  fields: [
    { field: 'roleLabel', enabled: true },
    { field: 'hostname', enabled: true },
    { field: 'ip', enabled: true },
    { field: 'mac', enabled: false },
    { field: 'deviceType', enabled: true },
    { field: 'manufacturer', enabled: false },
  ],
  customText: [],
};

/**
 * Normalise a persisted config so old shapes keep working:
 * - `customText` used to be a single string; coerce it to a string[].
 * - Fields added after the config was persisted (e.g. roleLabel) are appended with their default
 *   enabled flag, so new options appear without a manual reset. Appending (rather than positional
 *   insertion) keeps a user's own field ordering untouched; they can move the new field up.
 * - Fields no longer known are dropped.
 */
export function normalizeNodeLabelConfig(cfg: NodeLabelConfig): NodeLabelConfig {
  const raw = cfg?.customText as unknown;
  const customText = Array.isArray(raw)
    ? raw.filter(t => typeof t === 'string')
    : typeof raw === 'string' && raw.trim()
      ? [raw]
      : [];

  const persisted = (cfg?.fields ?? []).filter(f => f?.field != null && f.field in NODE_LABEL_FIELD_META);
  if (persisted.length === 0) return { fields: [...DEFAULT_NODE_LABEL_CONFIG.fields], customText };
  const missing = DEFAULT_NODE_LABEL_CONFIG.fields.filter(
    def => !persisted.some(f => f.field === def.field),
  );
  return { fields: [...persisted, ...missing.map(def => ({ ...def }))], customText };
}

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
