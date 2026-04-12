import { Handle, Position, type NodeProps } from '@xyflow/react';

export interface ClusterFlowNodeData extends Record<string, unknown> {
  label: string;
  clusterId: string;
  memberCount: number;
  statsText: string;
  hasAnomaly: boolean;
  roleBreakdown: { client: number; server: number; both: number; unknown: number };
  /** Called when the user clicks the expand button. */
  onExpand: (clusterId: string) => void;
  /** Which file(s) this cluster appears in — set only in compare mode. */
  sources?: string[];
  primarySource?: string;
}

export function ClusterNode({ data }: NodeProps) {
  const {
    label,
    clusterId,
    memberCount,
    statsText,
    hasAnomaly,
    roleBreakdown,
    onExpand,
    sources,
    primarySource,
  } = data as ClusterFlowNodeData;

  const isSecondaryOnly =
    sources?.length === 1 && primarySource !== undefined && sources[0] !== primarySource;
  const isShared = sources !== undefined && sources.length >= 2;

  const total = memberCount || 1;
  const clientPct = ((roleBreakdown?.client ?? 0) / total) * 100;
  const serverPct = ((roleBreakdown?.server ?? 0) / total) * 100;
  const bothPct = ((roleBreakdown?.both ?? 0) / total) * 100;
  const unknownPct = 100 - clientPct - serverPct - bothPct;

  return (
    <div
      className={`network-flow-cluster-node${hasAnomaly ? ' has-anomaly' : ''}`}
      style={{
        opacity: isSecondaryOnly ? 0.8 : 1,
        borderStyle: isSecondaryOnly ? 'dashed' : 'dashed', // always dashed for clusters
        borderColor: hasAnomaly ? '#e74c3c' : '#7f8c8d',
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="network-flow-handle"
        style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }}
      />
      <Handle
        type="source"
        position={Position.Top}
        className="network-flow-handle"
        style={{ top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }}
      />

      <button
        className="network-flow-cluster-expand"
        title="Expand cluster"
        onClick={e => {
          e.stopPropagation();
          onExpand(clusterId);
        }}
      >
        <i className="bi bi-arrows-angle-expand" />
      </button>

      <div className="network-flow-cluster-header">
        {hasAnomaly && (
          <i
            className="bi bi-exclamation-triangle-fill me-1"
            style={{ color: '#e74c3c', fontSize: 10 }}
          />
        )}
        {label}
        {isShared && (
          <i
            className="bi bi-layers-fill ms-1"
            style={{ fontSize: 9, color: '#6c757d', opacity: 0.85 }}
          />
        )}
      </div>

      <div className="network-flow-cluster-stats">{statsText}</div>

      {/* Role mini-bar */}
      <div
        className="network-flow-cluster-rolebar"
        title="Role breakdown: client / server / both / unknown"
      >
        {clientPct > 0 && (
          <div
            style={{ width: `${clientPct}%`, background: '#3498db' }}
            title={`${roleBreakdown?.client ?? 0} clients`}
          />
        )}
        {serverPct > 0 && (
          <div
            style={{ width: `${serverPct}%`, background: '#2ecc71' }}
            title={`${roleBreakdown?.server ?? 0} servers`}
          />
        )}
        {bothPct > 0 && (
          <div
            style={{ width: `${bothPct}%`, background: '#9b59b6' }}
            title={`${roleBreakdown?.both ?? 0} both`}
          />
        )}
        {unknownPct > 0 && <div style={{ width: `${unknownPct}%`, background: '#95a5a6' }} />}
      </div>
    </div>
  );
}
