export interface Network {
  id: string;
  name: string;
  description: string | null;
  snapshotCount: number;
  criticalChanges: number;
  warningChanges: number;
  createdAt: string;
  updatedAt: string;
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
  addedAt: string;
}

export type ChangeType =
  | 'MAC_ADDED'
  | 'IP_MAC_DRIFT'
  | 'ASN_CHANGE'
  | 'GATEWAY_CHANGE'
  | 'PROTOCOL_ADDED'
  | 'APP_ADDED'
  | 'VPN_DRIFT';

export type EntityType = 'DEVICE' | 'IP_MAC_BINDING' | 'ISP' | 'PROTOCOL' | 'APP';

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
}
