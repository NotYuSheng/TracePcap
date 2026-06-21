import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';

export type Tab = 'details' | 'notes';

export interface HostClassification {
  ip: string | null;
  mac: string | null;
  manufacturer: string | null;
  deviceType: string | null;
  confidence: number | null;
  ttl: number | null;
}

export interface IpSnapshotEntry {
  snap: NetworkSnapshot;
  host: HostClassification | null;
  apps: string[];
  protocols: string[];
}

export interface EntityStats {
  conversationCount: number;
  packetCount: number;
  totalBytes: number;
  /** Distinct peer IPs (for APPLICATION/PROTOCOL only) */
  topPeers: { ip: string; bytes: number }[];
}

export interface EntityDetailModalProps {
  entityType: EntityType;
  entityKey: string;
  /** Display label (may differ from key) */
  displayName: string;
  /** Current file ID — used to fetch stats and mark history rows */
  fileId: string;
  /** Badge element rendered in the modal header */
  badge?: React.ReactNode;
  /** Whether the entity was seen in the most recent snapshot (Monitor context) */
  isActive?: boolean;
  /** ISO timestamp of last seen time — used to compute "inactive X days ago" */
  lastSeenTime?: string | null;
  /** Called when "View conversations" is clicked */
  onViewConversations?: () => void;
  /** Monitor snapshots — when provided for IP type, shows per-snapshot MAC/device history */
  snapshots?: NetworkSnapshot[];
  onClose: () => void;
  zIndex?: number;
}
