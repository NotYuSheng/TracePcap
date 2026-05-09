import { useState, useEffect, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  useReactFlow,
  type Node,
  type Edge,
  type NodeProps,
  type EdgeProps,
  type NodeTypes,
  type EdgeTypes,
  type NodeMouseHandler,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './ClusterGraph.css';
import ELK from 'elkjs';
import { formatBytes } from '@/utils/formatters';
import type { ClusterGraphResponse, ClusterNode as ClusterNodeData, GroupBy } from '@/features/intelligence/services/intelligenceService';
import { conversationService } from '@/features/conversation/services/conversationService';
import type { Conversation } from '@/types';
import { ConversationTracerModal } from '@components/conversation/ConversationTracer/ConversationTracerModal';

// ── Layout ────────────────────────────────────────────────────────────────────

const elk = new ELK();

const NODE_WIDTH = 160;
const NODE_HEIGHT = 80;
const H_GAP = 200;
const V_GAP = 140;
const COLS = 6;

function parseOctets(prefix: string): number[] {
  return prefix.split('.').map(n => parseInt(n, 10) || 0);
}

function compareOctets(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/** Deterministic grid layout for subnet strategies, grouped by parent prefix. */
function computeSubnetLayout(nodes: Node[], groupBy: 'subnet24' | 'subnet16'): Node[] {
  const GROUP_EXTRA_GAP = 60;

  if (groupBy === 'subnet24') {
    const getPrefix = (id: string) => id.replace('subnet24:', '');
    const getParent = (prefix: string) => prefix.split('.').slice(0, 2).join('.');

    const groups = new Map<string, { prefix: string; node: Node }[]>();
    for (const node of nodes) {
      const prefix = getPrefix(node.id);
      const parent = getParent(prefix);
      const g = groups.get(parent) ?? [];
      g.push({ prefix, node });
      groups.set(parent, g);
    }

    const sortedGroups = [...groups.entries()].sort(([a], [b]) =>
      compareOctets(parseOctets(a), parseOctets(b))
    );

    const result: Node[] = [];
    let yOffset = 0;
    for (const [, members] of sortedGroups) {
      members.sort((a, b) => compareOctets(parseOctets(a.prefix), parseOctets(b.prefix)));
      members.forEach(({ node }, i) => {
        result.push({
          ...node,
          position: { x: (i % COLS) * H_GAP, y: yOffset + Math.floor(i / COLS) * V_GAP },
        });
      });
      yOffset += Math.ceil(members.length / COLS) * V_GAP + GROUP_EXTRA_GAP;
    }
    return result;
  }

  // subnet16: simple numeric sort → grid
  const getPrefix = (id: string) => id.replace('subnet16:', '');
  return [...nodes]
    .sort((a, b) => compareOctets(parseOctets(getPrefix(a.id)), parseOctets(getPrefix(b.id))))
    .map((node, i) => ({
      ...node,
      position: { x: (i % COLS) * H_GAP, y: Math.floor(i / COLS) * V_GAP },
    }));
}

async function runLayout(
  nodes: Node[],
  edges: Edge[],
  groupBy: GroupBy,
): Promise<{ nodes: Node[]; edges: Edge[] }> {
  const nodeIdSet = new Set(nodes.map(n => n.id));
  const validEdges = edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));

  // Subnet strategies + customOrg (which has subnet24 fallback nodes): deterministic grid
  if (groupBy === 'subnet24' || groupBy === 'subnet16' || groupBy === 'customOrg') {
    return { nodes: computeSubnetLayout(nodes, 'subnet24'), edges: validEdges };
  }

  // Other strategies: ELK force layout
  const graph = await elk.layout({
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'org.eclipse.elk.force',
      'elk.separateConnectedComponents': 'true',
      'elk.spacing.nodeNode': '80',
      'elk.force.iterations': '100',
      'elk.force.repulsion': '3.0',
    },
    children: nodes.map(n => ({ id: n.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
    edges: validEdges.map(e => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  });

  const posMap = new Map((graph.children ?? []).map(n => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]));
  return {
    nodes: nodes.map(n => ({ ...n, position: posMap.get(n.id) ?? { x: 0, y: 0 } })),
    edges: validEdges,
  };
}

// ── Group icons ───────────────────────────────────────────────────────────────

const GROUP_ICONS: Record<GroupBy, string> = {
  asn: 'bi-building',
  country: 'bi-geo-alt',
  subnet24: 'bi-hdd-network',
  subnet16: 'bi-hdd-network',
  deviceType: 'bi-cpu',
  customOrg: 'bi-tag',
};

// ── Color helpers ─────────────────────────────────────────────────────────────

type ColorMode = 'risk' | 'traffic';

/** Returns a blue shade interpolated by ratio (0→light, 1→dark). */
function trafficColor(ratio: number): string {
  // Interpolate from #d0e4f7 (light blue) to #1565c0 (dark blue)
  const r = Math.round(208 - ratio * (208 - 21));
  const g = Math.round(228 - ratio * (228 - 101));
  const b = Math.round(247 - ratio * (247 - 192));
  return `rgb(${r},${g},${b})`;
}

// ── Custom node ───────────────────────────────────────────────────────────────

interface IntelClusterNodeData extends Record<string, unknown> {
  label: string;
  hostCount: number;
  totalBytes: number;
  riskCount: number;
  topRiskTypes: string[];
  dominantProtocols: string[];
  groupType: string;
  selected: boolean;
  colorMode: ColorMode;
  trafficRatio: number; // 0-1, totalBytes / maxBytes across all clusters
}

function IntelClusterNode({ data }: NodeProps) {
  const d = data as IntelClusterNodeData;
  const hasRisk = d.riskCount > 0;
  const icon = GROUP_ICONS[d.groupType as GroupBy] ?? 'bi-diagram-3';

  const isTrafficMode = d.colorMode === 'traffic';
  const bgColor = isTrafficMode ? trafficColor(d.trafficRatio) : undefined;
  const textColor = isTrafficMode
    ? (d.trafficRatio > 0.55 ? '#fff' : '#212529')
    : (hasRisk ? '#e74c3c' : '#495057');

  const riskTitle = hasRisk
    ? `${d.riskCount} risk alert${d.riskCount !== 1 ? 's' : ''}${
        d.topRiskTypes?.length ? '\n' + d.topRiskTypes.join('\n') : ''
      }`
    : undefined;

  return (
    <div
      className={`intel-cluster-node${hasRisk && !isTrafficMode ? ' has-risk' : ''}${d.selected ? ' selected' : ''}`}
      style={bgColor ? { background: bgColor, borderColor: bgColor } : undefined}
    >
      <Handle type="target" position={Position.Top} className="intel-handle" style={{ top: '50%', left: '50%', transform: 'translate(-50%,-50%)' }} />
      <Handle type="source" position={Position.Top} className="intel-handle" style={{ top: '50%', left: '50%', transform: 'translate(-50%,-50%)' }} />

      {hasRisk && (
        <span className="intel-cluster-risk-badge" title={riskTitle} style={{ color: isTrafficMode && d.trafficRatio > 0.55 ? '#ffcdd2' : '#e74c3c' }}>
          <i className="bi bi-exclamation-triangle-fill" />
        </span>
      )}

      <div className="intel-cluster-header" style={{ color: textColor }}>
        <i className={`bi ${icon}`} style={{ color: textColor }} />
        <span className="intel-cluster-label" title={d.label}>{d.label}</span>
      </div>

      <div className="intel-cluster-stats" style={isTrafficMode ? { color: textColor, opacity: 0.85 } : undefined}>
        {d.hostCount.toLocaleString()} host{d.hostCount !== 1 ? 's' : ''} · {formatBytes(d.totalBytes)}
      </div>

      {d.dominantProtocols.length > 0 && (
        <div className="intel-cluster-protocols">
          {d.dominantProtocols.slice(0, 3).map(p => (
            <span key={p} className={`intel-cluster-badge${isTrafficMode && d.trafficRatio > 0.55 ? ' intel-cluster-badge-dark' : ''}`}>{p}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Custom straight edge ──────────────────────────────────────────────────────

function IntelEdge({ id, sourceX, sourceY, targetX, targetY, data, style }: EdgeProps) {
  const label = (data as { label?: string } | undefined)?.label;
  const path = `M ${sourceX},${sourceY} L ${targetX},${targetY}`;
  const midX = (sourceX + targetX) / 2;
  const midY = (sourceY + targetY) / 2;

  return (
    <>
      <BaseEdge id={id} path={path} style={style} />
      {label && (
        <EdgeLabelRenderer>
          <div
            className="intel-edge-label nodrag nopan"
            style={{ transform: `translate(-50%,-50%) translate(${midX}px,${midY}px)` }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

const nodeTypes: NodeTypes = { intelCluster: IntelClusterNode };
const edgeTypes: EdgeTypes = { intelEdge: IntelEdge };

// ── Auto fit-view after layout ────────────────────────────────────────────────

function AutoFitView({ version }: { version: number }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    if (version === 0) return;
    const t = setTimeout(() => fitView({ padding: 0.15, duration: 300 }), 50);
    return () => clearTimeout(t);
  }, [version, fitView]);
  return null;
}

// ── GROUP-BY options ──────────────────────────────────────────────────────────

const GROUP_BY_OPTIONS: { value: GroupBy; label: string }[] = [
  { value: 'asn', label: 'ASN / Organization' },
  { value: 'country', label: 'Country' },
  { value: 'subnet24', label: 'Subnet /24' },
  { value: 'subnet16', label: 'Subnet /16' },
  { value: 'deviceType', label: 'Device Type' },
  { value: 'customOrg', label: 'Network Labels ★' },
];

// ── Side panel ────────────────────────────────────────────────────────────────

interface ClusterPanelProps {
  cluster: ClusterNodeData;
  fileId: string;
  onClose: () => void;
  onTrace: (conversationId: string) => void;
}

function ClusterPanel({ cluster, fileId, onClose, onTrace }: ClusterPanelProps) {
  const [convos, setConvos] = useState<Conversation[]>([]);
  const [convosLoading, setConvosLoading] = useState(false);
  type IpMetric = 'bytes' | 'conversations' | 'risks' | 'peers';
  const [ipMetric, setIpMetric] = useState<IpMetric>('bytes');

  useEffect(() => {
    if (!cluster.sampleIps.length) return;
    setConvosLoading(true);
    conversationService
      .getConversations(fileId, {
        ip: cluster.sampleIps[0],
        port: '', payloadContains: '',
        protocols: [], l7Protocols: [], apps: [],
        categories: [], hasRisks: false, fileTypes: [],
        riskTypes: [], customSignatures: [], deviceTypes: [],
        countries: [], sortBy: 'bytes', sortDir: 'desc',
        page: 1, pageSize: 8,
      })
      .then(r => setConvos(r.data))
      .catch(console.error)
      .finally(() => setConvosLoading(false));
  }, [cluster.id, fileId]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div
      style={{
        position: 'absolute',
        top: 10,
        right: 10,
        width: 300,
        zIndex: 10,
        background: 'var(--tp-surface, #fff)',
        border: '1px solid var(--tp-border, #dee2e6)',
        borderRadius: 8,
        boxShadow: '0 4px 16px rgba(0,0,0,0.15)',
        fontSize: 13,
        display: 'flex',
        flexDirection: 'column',
        maxHeight: 480,
      }}
    >
      <div className="d-flex justify-content-between align-items-start p-3 pb-2">
        <strong style={{ fontSize: 13 }}>{cluster.label}</strong>
        <button className="btn-close btn-sm" onClick={onClose} />
      </div>

      <div className="px-3 pb-2">
        <table className="table table-sm table-borderless mb-0" style={{ fontSize: 12 }}>
          <tbody>
            <tr><td className="text-muted ps-0">Hosts</td><td>{cluster.hostCount.toLocaleString()}</td></tr>
            <tr><td className="text-muted ps-0">Traffic</td><td>{formatBytes(cluster.totalBytes)}</td></tr>
            <tr><td className="text-muted ps-0">Conversations</td><td>{cluster.conversationCount.toLocaleString()}</td></tr>
            {cluster.riskCount > 0 && (
              <tr>
                <td className="text-muted ps-0">Risks</td>
                <td className="text-danger fw-semibold">
                  {cluster.riskCount}
                  {cluster.topRiskTypes?.length > 0 && (
                    <div className="text-muted fw-normal mt-1" style={{ fontSize: 10 }}>
                      {cluster.topRiskTypes.map(rt => (
                        <div key={rt} style={{ fontFamily: 'monospace' }}>{rt}</div>
                      ))}
                    </div>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>

        {cluster.dominantProtocols.length > 0 && (
          <div className="d-flex flex-wrap gap-1 mb-1">
            {cluster.dominantProtocols.map(p => (
              <span key={p} className="badge bg-primary-subtle text-primary-emphasis" style={{ fontSize: 10 }}>{p}</span>
            ))}
          </div>
        )}

        {cluster.sampleIps.length > 0 && (
          <div className="mt-1">
            <div className="d-flex align-items-center justify-content-between mb-1">
              <small className="text-muted">Top hosts by</small>
              <select
                className="form-select form-select-sm"
                style={{ width: 120, fontSize: 10, padding: '1px 4px' }}
                value={ipMetric}
                onChange={e => setIpMetric(e.target.value as IpMetric)}
              >
                <option value="bytes">Traffic</option>
                <option value="conversations">Conversations</option>
                <option value="risks">Risk flags</option>
                <option value="peers">Unique peers</option>
              </select>
            </div>
            {[...cluster.sampleIps]
              .sort((a, b) => {
                const map = ipMetric === 'bytes' ? cluster.ipBytes
                  : ipMetric === 'conversations' ? cluster.ipConversations
                  : ipMetric === 'risks' ? cluster.ipRisks
                  : cluster.ipPeers;
                return (map?.[b] ?? 0) - (map?.[a] ?? 0);
              })
              .slice(0, 5)
              .map(ip => {
                const map = ipMetric === 'bytes' ? cluster.ipBytes
                  : ipMetric === 'conversations' ? cluster.ipConversations
                  : ipMetric === 'risks' ? cluster.ipRisks
                  : cluster.ipPeers;
                const val = map?.[ip];
                const valStr = val == null ? '' : ipMetric === 'bytes' ? formatBytes(val) : val.toLocaleString();
                return (
                  <div key={ip} className="d-flex justify-content-between" style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--tp-text, #212529)' }}>
                    <span>{ip}</span>
                    {valStr && <span className="text-muted ms-2">{valStr}</span>}
                  </div>
                );
              })
            }
            {cluster.hostCount > cluster.sampleIps.length && (
              <small className="text-muted">…and {(cluster.hostCount - cluster.sampleIps.length).toLocaleString()} more</small>
            )}
          </div>
        )}
      </div>

      <div style={{ borderTop: '1px solid var(--tp-border, #dee2e6)', flex: 1, overflowY: 'auto' }}>
        <div className="px-3 py-2 d-flex align-items-center gap-2">
          <small className="fw-semibold text-muted" style={{ fontSize: 10, letterSpacing: '0.04em' }}>TOP CONVERSATIONS</small>
          {convosLoading && <span className="spinner-border spinner-border-sm text-secondary" style={{ width: 12, height: 12, borderWidth: 2 }} />}
        </div>
        {convos.length === 0 && !convosLoading && (
          <p className="text-muted small px-3">No conversations found.</p>
        )}
        {convos.map(c => {
          const src = c.endpoints[0];
          const dst = c.endpoints[1];
          return (
            <div
              key={c.id}
              className="px-3 py-2 d-flex align-items-center gap-2"
              style={{ borderBottom: '1px solid #f0f0f0', fontSize: 11 }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'monospace', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {src.ip}:{src.port} → {dst.ip}:{dst.port}
                </div>
                <div className="text-muted" style={{ fontSize: 10 }}>
                  {c.protocol.name}{c.appName ? ` / ${c.appName}` : ''} · {formatBytes(c.totalBytes)}
                </div>
              </div>
              <button
                className="btn btn-outline-primary btn-sm flex-shrink-0"
                style={{ fontSize: 10, padding: '2px 8px' }}
                onClick={() => onTrace(c.id)}
                title="Trace this conversation"
              >
                <i className="bi bi-play-circle me-1" />
                Trace
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface ClusterGraphProps {
  data: ClusterGraphResponse | null;
  loading: boolean;
  groupBy: GroupBy;
  onGroupByChange: (g: GroupBy) => void;
  fileId: string;
}

const COLOR_MODE_OPTIONS: { value: ColorMode; label: string }[] = [
  { value: 'risk', label: 'Risk alerts' },
  { value: 'traffic', label: 'Traffic volume' },
];

export const ClusterGraph = ({ data, loading, groupBy, onGroupByChange, fileId }: ClusterGraphProps) => {
  const [rfNodes, setRfNodes] = useState<Node[]>([]);
  const [rfEdges, setRfEdges] = useState<Edge[]>([]);
  const [selectedCluster, setSelectedCluster] = useState<ClusterNodeData | null>(null);
  const [layoutLoading, setLayoutLoading] = useState(false);
  const [tracerConversationId, setTracerConversationId] = useState<string | null>(null);
  const [colorMode, setColorMode] = useState<ColorMode>('traffic');
  const [layoutVersion, setLayoutVersion] = useState(0);

  const clusterById = new Map((data?.clusters ?? []).map(c => [c.id, c]));

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    const cluster = clusterById.get(node.id);
    setSelectedCluster(prev => prev?.id === node.id ? null : (cluster ?? null));
  }, [data]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!data || data.clusters.length === 0) {
      setRfNodes([]);
      setRfEdges([]);
      setSelectedCluster(null);
      return;
    }

    setLayoutLoading(true);

    const MAX_EDGE_BYTES = Math.max(...data.edges.map(e => e.totalBytes), 1);
    const MAX_NODE_BYTES = Math.max(...data.clusters.map(c => c.totalBytes), 1);

    const rawNodes: Node[] = data.clusters.map(c => ({
      id: c.id,
      type: 'intelCluster',
      position: { x: 0, y: 0 },
      data: {
        label: c.label,
        hostCount: c.hostCount,
        totalBytes: c.totalBytes,
        riskCount: c.riskCount,
        topRiskTypes: c.topRiskTypes ?? [],
        dominantProtocols: c.dominantProtocols,
        groupType: c.groupType,
        selected: selectedCluster?.id === c.id,
        colorMode,
        trafficRatio: c.totalBytes / MAX_NODE_BYTES,
      } satisfies IntelClusterNodeData,
    }));

    const rawEdges: Edge[] = data.edges.map(e => ({
      id: `${e.sourceId}|||${e.targetId}`,
      source: e.sourceId,
      target: e.targetId,
      type: 'intelEdge',
      data: { label: e.dominantProtocol ?? undefined },
      style: {
        strokeWidth: 1 + Math.round((e.totalBytes / MAX_EDGE_BYTES) * 4),
        stroke: '#adb5bd',
      },
    }));

    runLayout(rawNodes, rawEdges, groupBy)
      .then(({ nodes, edges }) => {
        setRfNodes(nodes);
        setRfEdges(edges);
        setLayoutVersion(v => v + 1);
      })
      .catch(console.error)
      .finally(() => setLayoutLoading(false));
  }, [data, groupBy, colorMode]); // eslint-disable-line react-hooks/exhaustive-deps

  // Update selected state on nodes without re-running layout
  useEffect(() => {
    setRfNodes(prev => prev.map(n => ({
      ...n,
      data: { ...n.data, selected: selectedCluster?.id === n.id },
    })));
  }, [selectedCluster]);

  const isEmpty = !loading && rfNodes.length === 0 && !layoutLoading;

  return (
    <div className="intel-cluster-graph-wrapper">
      {/* Controls bar */}
      <div className="d-flex align-items-center gap-3 mb-3">
        <label className="form-label mb-0 text-muted small">Group by</label>
        <select
          className="form-select form-select-sm"
          style={{ width: 200 }}
          value={groupBy}
          onChange={e => onGroupByChange(e.target.value as GroupBy)}
          disabled={loading}
        >
          {GROUP_BY_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>

        <label className="form-label mb-0 text-muted small ms-2">Color by</label>
        <select
          className="form-select form-select-sm"
          style={{ width: 160 }}
          value={colorMode}
          onChange={e => setColorMode(e.target.value as ColorMode)}
        >
          {COLOR_MODE_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>

        {data && !loading && (
          <div className="d-flex align-items-center gap-2">
            <small className="text-muted">
              {data.clusters.length} cluster{data.clusters.length !== 1 ? 's' : ''},{' '}
              {data.edges.length} connection{data.edges.length !== 1 ? 's' : ''}
            </small>
            {data.hiddenClusters > 0 && (
              <span
                className="badge bg-secondary"
                style={{ fontSize: 10 }}
                title="Showing top clusters by traffic volume"
              >
                +{data.hiddenClusters} smaller hidden
              </span>
            )}
          </div>
        )}

        {(loading || layoutLoading) && (
          <span className="spinner-border spinner-border-sm text-primary" role="status" />
        )}
      </div>

      {/* Hint for Network Labels grouping */}
      {groupBy === 'customOrg' && (
        <div className="alert alert-info py-2 mb-3 d-flex align-items-center gap-2" style={{ fontSize: 13 }}>
          <i className="bi bi-tag-fill flex-shrink-0" />
          <span>
            Network Labels are defined in{' '}
            <strong>Custom Detection Rules</strong> — open it from the navigation bar and go to the{' '}
            <strong>Network Labels</strong> tab to add or edit IP ranges.
          </span>
        </div>
      )}

      {/* Hint when geo-based grouping yields only internal traffic */}
      {data && !loading &&
        (groupBy === 'asn' || groupBy === 'country') &&
        data.clusters.length <= 2 &&
        data.clusters.every(c => c.label.startsWith('Internal')) && (
        <div className="alert alert-info py-2 mb-3 d-flex align-items-center gap-2" style={{ fontSize: 13 }}>
          <i className="bi bi-info-circle-fill" />
          <span>
            All hosts are on an internal/private network — {groupBy === 'asn' ? 'ASN' : 'Country'} grouping
            has no external data to show. Try{' '}
            <strong>Subnet /24</strong> or <strong>Device Type</strong> for a meaningful view.
          </span>
          <button className="btn btn-sm btn-info ms-auto" onClick={() => onGroupByChange('subnet24')}>
            Switch to Subnet /24
          </button>
        </div>
      )}

      {/* Graph canvas */}
      {isEmpty ? (
        <div className="intel-graph-empty">
          <i className="bi bi-diagram-3 mb-2" style={{ fontSize: 32, opacity: 0.3 }} />
          <span>No cluster data available</span>
        </div>
      ) : (
        <div className="intel-graph-container">
          {(loading || layoutLoading) && (
            <div className="intel-graph-layouting">
              <span className="spinner-border spinner-border-sm" />
              Computing layout…
            </div>
          )}

          {selectedCluster && (
            <ClusterPanel
              cluster={selectedCluster}
              fileId={fileId}
              onClose={() => setSelectedCluster(null)}
              onTrace={id => setTracerConversationId(id)}
            />
          )}

          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodeClick={handleNodeClick}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.1}
            maxZoom={3}
            nodesDraggable
            nodesConnectable={false}
            elementsSelectable={false}
          >
            <Background color="#e9ecef" gap={20} />
            <Controls showInteractive={false} />
            <AutoFitView version={layoutVersion} />
          </ReactFlow>
        </div>
      )}

      {/* Conversation Tracer modal */}
      {tracerConversationId && (
        <ConversationTracerModal
          conversationId={tracerConversationId}
          fileId={fileId}
          onClose={() => setTracerConversationId(null)}
        />
      )}
    </div>
  );
};
