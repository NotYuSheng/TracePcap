import type { EntityType } from '@/features/notes/services/entityNotesService';
import type { NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';

/** Base tabs; graph context adds a 'history' tab and dynamic `svc:<role>` service tabs. The
 *  `string & {}` keeps literal autocomplete for the known names while still allowing `svc:<role>`. */
export type Tab = 'details' | 'notes' | 'history' | (string & {});

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
  /** Per-snapshot role label (#369), its origin, and whether it was flagged stale in this snapshot. */
  roleLabel: string | null;
  roleOrigin: string | null; // MANUAL | AI | CARRIED_FORWARD
  roleStale: boolean;
  /** All distinct MACs that claimed this IP in the snapshot; >1 ⇒ overlap/conflict (#461). */
  macs: string[];
  /** For a DEVICE entity: all distinct IPs this MAC used in the snapshot; >1 ⇒ conflict (#461). */
  ips: string[];
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
  /** File name of the snapshot the entity was last seen in (Monitor context) */
  lastSeenFileName?: string | null;
  /** Called when "View conversations" is clicked */
  onViewConversations?: () => void;
  /** Monitor snapshots — when provided for IP type, shows per-snapshot MAC/device history */
  snapshots?: NetworkSnapshot[];
  onClose: () => void;
  zIndex?: number;

  // ── Graph context (network-diagram surfaces) ─────────────────────────────────
  // When `graphNode` is supplied, the modal renders the network-graph host detail: measured traffic
  // counters, protocol chips, a per-peer Connections table (from `graphEdges`), the History tab, and
  // any service-role log tabs — the pieces that used to live in the standalone NodeDetails. Omit them
  // and the modal is the plain entity panel (monitor drift / analysis).
  /** The clicked graph node; presence switches on all graph-only sections. */
  graphNode?: GraphNode;
  /** All graph edges, for building this node's per-peer Connections table. */
  graphEdges?: GraphEdge[];
  /** Change-event highlight banner (Monitor snapshot / Compare diff context). */
  changeHighlight?: NodeHighlight;
  /** Navigate away (peer-row / history-row links). Given a path; the caller routes + closes. */
  onNavigate?: (path: string) => void;
}
