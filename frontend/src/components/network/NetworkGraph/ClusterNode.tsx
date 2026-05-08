/**
 * ClusterFlowNodeData — data shape passed to the cluster custom node type.
 * Rendering is handled by ClusterNodeComp inside NetworkGraph.tsx.
 */
export interface ClusterFlowNodeData {
  label: string;
  clusterId: string;
  memberCount: number;
  color: string;
  riskCount?: number;
  dominantProtocols?: string[];
  roleBreakdown?: { client: number; server: number; both: number; unknown: number };
  onExpand?: () => void;
  sources?: string[];
  primarySource?: string;
}
