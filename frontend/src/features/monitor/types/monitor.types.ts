export interface Network {
  id: string;
  name: string;
  description: string | null;
  snapshotCount: number;
  criticalChanges: number;
  warningChanges: number;
  hasInsights: boolean;
  createdAt: string;
  updatedAt: string;
  /** Per-network settings (#488). Absent on old responses: treat as DEFAULT_NETWORK_SETTINGS. */
  settings?: NetworkSettings;
  /** Each capture in order, with the most severe change it brought (the first is the baseline). */
  captures?: CaptureMark[];
}

export interface CaptureMark {
  snapshotId: string;
  fileName: string;
  capturedAt: string | number[] | null;
  baseline: boolean;
  changes: 'NONE' | 'INFO' | 'WARNING' | 'CRITICAL';
}

/**
 * Per-network settings (#468, #488). The inactivity rule decides when something missing from the
 * latest capture stops being "quiet" and becomes "no longer seen".
 */
export interface NetworkSettings {
  /** SNAPSHOTS: count missed captures. DAYS: count days before the latest capture. */
  inactivityMode: 'SNAPSHOTS' | 'DAYS';
  /** A capture count for SNAPSHOTS, a day count for DAYS. At least 1. */
  inactivityThreshold: number;
}

export interface SubnetOverride {
  id: number | null;
  cidr: string;
  label: string | null;
  description: string | null;
  inherited: boolean;
}

export interface SubnetOverrideInput {
  cidr: string;
  label: string | null;
  description: string | null;
  inherited: boolean;
}

export interface NetworkSnapshot {
  id: string;
  networkId: string;
  fileId: string;
  fileName: string;
  snapshotOrder: number;
  startTime: string | null;
  endTime: string | null;
  packetCount: number | null;
  totalBytes: number | null;
  changeCount: number;
  criticalCount: number;
  /** Distinct absolute security signals in this capture (IDS/risks/sigs/file types). */
  securitySignalCount: number;
  context: string | null;
  notes: string | null;
  hasInsights: boolean;
  addedAt: string;
  subnetOverrides: SubnetOverride[];
}

export type ChangeType =
  | 'MAC_ADDED'
  | 'IP_MAC_DRIFT'
  | 'ASN_CHANGE'
  | 'GATEWAY_CHANGE'
  | 'PROTOCOL_ADDED'
  | 'APP_ADDED'
  | 'VPN_DRIFT'
  | 'SECURITY_ALERT_ADDED'
  | 'SECURITY_ALERT_REMOVED'
  | 'LABEL_STALE'
  | 'BASELINE_MISSING'
  | 'BASELINE_MISMATCH';

export type EntityType =
  | 'DEVICE' | 'IP_MAC_BINDING' | 'ISP' | 'PROTOCOL' | 'APP' | 'SECURITY' | 'NODE_ROLE';

export type Severity = 'INFO' | 'WARNING' | 'CRITICAL';

export interface ChangeEvent {
  id: string;
  networkId: string;
  fromSnapshotId: string | null;
  toSnapshotId: string;
  changeType: ChangeType;
  entityType: EntityType;
  entityKey: string;
  oldValue: Record<string, unknown> | null;
  newValue: Record<string, unknown> | null;
  severity: Severity;
  detectedAt: string;
  reviewed: boolean;
  notes: string | null;
}

export type BaselineEntryType =
  | 'DEVICE'
  | 'IP_MAC_BINDING'
  | 'GATEWAY'
  | 'PROTOCOL'
  | 'APP'
  | 'VPN_FINGERPRINT';

export interface BaselineDefinition {
  id: string;
  networkId: string;
  entryType: BaselineEntryType;
  entityKey: string;
  entityValue: string | null;
  notes: string | null;
  createdAt: string;
}

/**
 * An entity (device / app / protocol) that was once seen in the network but is absent from the
 * most recent snapshot. Computed on the frontend from the changeEvents list.
 */
export interface AbsentEntity {
  key: string;
  type: 'DEVICE' | 'APP' | 'PROTOCOL' | 'IP';
  lastSeenFileName: string;
  lastSeenStartTime: string | null;
  lastSeenFileId: string | null;
  /** Quiet (still within the network's inactivity rule) or gone (#488). Gone when unset. */
  presence?: 'quiet' | 'gone';
}
