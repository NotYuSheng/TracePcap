export interface SubnetDefinition {
  id: number | null;
  cidr: string;
  label: string | null;
  description: string | null;
  source: 'AUTO' | 'MANUAL';
  confirmed: boolean;
  hostCount?: number;
  densityScore?: number;
  snapshotsSeen?: number;
  totalSnapshots?: number;
  labeledAt?: string | null;
  staleSince?: string | null;
  staleFields?: string[] | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface SubnetLabelSuggestion {
  label: string | null;
  description: string | null;
  memberCount: number;
  snapshotCount: number;
}

/** Evidence that a CIDR may span two overlapping networks (a member IP claimed by >1 MAC). */
export interface SubnetOverlapWarning {
  subnetId: number;
  cidr: string;
  conflictingIp: string;
  macs: string[];
  snapshotOrder: number;
  snapshotFileName: string;
}

/** One snapshot's view of a subnet's composition, for the Snapshot History table. */
export interface SubnetCompositionHistoryEntry {
  snapshotId: string;
  fileId: string;
  fileName: string;
  snapshotOrder: number;
  memberCount: number;
  deviceTypes: string[];
  protocols: string[];
}
