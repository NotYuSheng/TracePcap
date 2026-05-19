import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect, useCallback, useRef } from 'react';
import { Alert, Badge, Button, Form } from '@govtechsg/sgds-react';
import { createPortal } from 'react-dom';
import { useNavigate } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  BaseEdge,
  EdgeLabelRenderer,
  useReactFlow,
  applyNodeChanges,
  type Node,
  type Edge,
  type NodeProps,
  type EdgeProps,
  type NodeTypes,
  type EdgeTypes,
  type NodeMouseHandler,
  type OnNodesChange,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './ClusterGraph.css';
import ELK from 'elkjs';
import { formatBytes } from '@/utils/formatters';
import type { ClusterGraphResponse, ClusterNode as ClusterNodeData, GroupBy } from '@/features/intelligence/services/intelligenceService';
import { conversationService } from '@/features/conversation/services/conversationService';
import type { Conversation } from '@/types';
import { CountryMapView } from './CountryMapView';

// ── Geo source badge ──────────────────────────────────────────────────────────

const GEO_SOURCE_INFO: Record<string, { label: string; title: string; description: string; bg: string }> = {
  ipinfo: {
    label: 'ipinfo.io',
    title: 'Geo source: ipinfo.io',
    description: 'Location was resolved by calling the ipinfo.io API. This is an online feature — an internet connection is required. Results are cached locally so repeat lookups do not require another API call.',
    bg: '#198754',
  },
  mmdb: {
    label: 'Offline DB',
    title: 'Geo source: Offline database',
    description: 'Location was resolved using the bundled DB-IP Lite database. This happens when the app is offline or ipinfo.io could not be reached. Accuracy may be lower, especially for cloud provider IPs.',
    bg: '#6c757d',
  },
};

const GEO_SOURCE_FALLBACK = GEO_SOURCE_INFO.mmdb;

function GeoSourceBadge({ source }: { source?: string | null }) {
  const [popoverPos, setPopoverPos] = useState<{ top: number; left: number } | null>(null);
  const info = (source ? GEO_SOURCE_INFO[source] : undefined) ?? GEO_SOURCE_FALLBACK;

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (popoverPos) { setPopoverPos(null); return; }
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const popW = 260;
    const popH = 120; // rough estimate
    const left = Math.min(rect.right - popW, window.innerWidth - popW - 8);
    const top = rect.bottom + 6 + popH > window.innerHeight
      ? rect.top - popH - 6
      : rect.bottom + 6;
    setPopoverPos({ top, left: Math.max(8, left) });
  };

  return (
    <>
      <span
        className="ms-2 badge"
        style={{ backgroundColor: info.bg, color: '#fff', fontSize: '0.7em', cursor: 'pointer', verticalAlign: 'middle' }}
        onClick={handleClick}
      >
        {info.label}
      </span>
      {popoverPos && createPortal(
        <div
          style={{
            position: 'fixed',
            top: popoverPos.top,
            left: popoverPos.left,
            zIndex: 9999,
            background: 'var(--tp-surface, #fff)',
            border: '1px solid var(--tp-border, #dee2e6)',
            borderRadius: 6,
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            padding: '8px 10px',
            width: 260,
            fontSize: 11,
            color: 'var(--tp-text, #212529)',
          }}
          onClick={e => e.stopPropagation()}
        >
          <strong style={{ fontSize: 12 }}>{info.title}</strong>
          <p style={{ margin: '4px 0 0' }}>{info.description}</p>
          <Button
            size="sm"
            variant="outline-secondary"
            style={{ marginTop: 6, fontSize: 10, padding: '1px 6px', cursor: 'pointer' }}
            onClick={() => setPopoverPos(null)}
          >
            Close
          </Button>
        </div>,
        document.body
      )}
    </>
  );
}

// ── Layout ────────────────────────────────────────────────────────────────────

const elk = new ELK();

const NODE_WIDTH = 160;
const NODE_HEIGHT = 80;
const H_GAP = 200;
const V_GAP = 140;


// ── Panel layout (grouped swimlanes with per-group ELK force) ─────────────────
// Groups nodes by a key function, lays each group out independently with ELK
// force, then tiles the panels in a 3-column grid with background swimlanes.
async function computePanelLayout(
  nodes: Node[],
  edges: Edge[],
  getGroup: (node: Node) => string,   // returns group key for a node
  getLabel: (key: string, members: Node[]) => string, // human-readable group label
): Promise<{ nodes: Node[]; edges: Edge[] }> {
  const PAD = 40;
  const PANEL_GAP = 80;
  const LABEL_H = 32;
  const PANEL_COLS = 3;

  const nodeIdSet = new Set(nodes.map(n => n.id));
  const validEdges = edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));

  // Group nodes
  const groups = new Map<string, Node[]>();
  for (const node of nodes) {
    const key = getGroup(node);
    const g = groups.get(key) ?? [];
    g.push(node);
    groups.set(key, g);
  }
  const sortedGroups = [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));

  // Layout each subgraph independently with ELK force, normalised to (0,0)
  type Panel = { key: string; subNodes: Node[]; w: number; h: number };
  const panels: Panel[] = [];
  for (const [key, members] of sortedGroups) {
    const memberIds = new Set(members.map(n => n.id));
    const subEdges = validEdges.filter(e => memberIds.has(e.source) && memberIds.has(e.target));
    let subNodes: Node[];
    try {
      const graph = await elk.layout({
        id: 'root',
        layoutOptions: {
          'elk.algorithm': 'org.eclipse.elk.force',
          'elk.separateConnectedComponents': 'true',
          'elk.spacing.nodeNode': '60',
          'elk.force.iterations': '80',
          'elk.force.repulsion': '5.0',
        },
        children: members.map(n => ({ id: n.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
        edges: subEdges.map(e => ({ id: e.id, sources: [e.source], targets: [e.target] })),
      });
      const posMap = new Map((graph.children ?? []).map(n => [n.id, { x: n.x ?? 0, y: n.y ?? 0 }]));
      subNodes = members.map(n => ({ ...n, position: posMap.get(n.id) ?? { x: 0, y: 0 } }));
    } catch {
      subNodes = members.map((n, i) => ({ ...n, position: { x: (i % 2) * H_GAP, y: Math.floor(i / 2) * V_GAP } }));
    }
    const minX = Math.min(...subNodes.map(n => n.position.x));
    const minY = Math.min(...subNodes.map(n => n.position.y));
    subNodes = subNodes.map(n => ({ ...n, position: { x: n.position.x - minX, y: n.position.y - minY } }));
    const w = Math.max(...subNodes.map(n => n.position.x + NODE_WIDTH));
    const h = Math.max(...subNodes.map(n => n.position.y + NODE_HEIGHT));
    panels.push({ key, subNodes, w, h });
  }

  // Tile in a grid, computing row heights dynamically
  const rowHeights: number[] = [];
  const panelPositions: { x: number; y: number }[] = [];
  for (let i = 0; i < panels.length; i++) {
    const col = i % PANEL_COLS;
    const row = Math.floor(i / PANEL_COLS);
    if (col === 0) rowHeights[row] = 0;
    let x = 0;
    for (let c = 0; c < col; c++) {
      x += panels[row * PANEL_COLS + c].w + 2 * PAD + PANEL_GAP;
    }
    let y = 0;
    for (let r = 0; r < row; r++) {
      y += (rowHeights[r] ?? 0) + 2 * PAD + LABEL_H + PANEL_GAP;
    }
    rowHeights[row] = Math.max(rowHeights[row] ?? 0, panels[i].h);
    panelPositions.push({ x, y });
  }

  // Build final nodes with swimlane backgrounds
  const laidOutNodes: Node[] = [];
  const swimlanes: Node[] = [];
  for (let i = 0; i < panels.length; i++) {
    const { key, subNodes } = panels[i];
    const { x: px, y: py } = panelPositions[i];
    const panelW = panels[i].w + 2 * PAD;
    const panelH = panels[i].h + 2 * PAD + LABEL_H;
    const label = getLabel(key, subNodes);
    swimlanes.push({
      id: `__lane__${key}`,
      type: 'groupLabel',
      position: { x: px, y: py },
      data: { label, width: panelW, height: panelH },
      selectable: false,
      draggable: false,
      zIndex: -1,
      style: { width: panelW, height: panelH, pointerEvents: 'none' },
    });
    for (const node of subNodes) {
      laidOutNodes.push({
        ...node,
        position: { x: px + PAD + node.position.x, y: py + LABEL_H + PAD + node.position.y },
      });
    }
  }
  return { nodes: [...swimlanes, ...laidOutNodes], edges: validEdges };
}

async function runLayout(
  nodes: Node[],
  edges: Edge[],
  groupBy: GroupBy,
): Promise<{ nodes: Node[]; edges: Edge[] }> {
  const nodeIdSet = new Set(nodes.map(n => n.id));
  const validEdges = edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));

  // subnet24: group by /16 parent (first two octets)
  if (groupBy === 'subnet24') {
    return computePanelLayout(
      nodes, edges,
      node => node.id.replace('subnet24:', '').split('.').slice(0, 2).join('.'),
      key => `${key}.0.0 /16`,
    );
  }

  // subnet16: group by first octet
  if (groupBy === 'subnet16') {
    return computePanelLayout(
      nodes, edges,
      node => node.id.replace('subnet16:', '').split('.')[0],
      key => `${key}.0.0.0 /8`,
    );
  }

  // customOrg: group by org name (everything after 'customOrg:'); subnet24 fallbacks group together
  if (groupBy === 'customOrg') {
    return computePanelLayout(
      nodes, edges,
      node => node.id.startsWith('customOrg:') ? node.id.slice(10) : '(Unassigned)',
      key => key,
    );
  }

  // city: group by country code
  if (groupBy === 'city') {
    return computePanelLayout(
      nodes, edges,
      node => node.id.split(':')[1] ?? '??',
      (key, members) => members[0].data.label?.toString().split(', ').slice(1).join(', ') || key,
    );
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
  city: 'bi-pin-map',
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

function GroupLabelNode({ data }: NodeProps) {
  const d = data as { label: string; width: number; height: number };
  return (
    <div style={{
      width: d.width, height: d.height,
      border: '1.5px solid var(--tp-border, #dee2e6)',
      borderRadius: 10,
      background: 'var(--tp-bg-subtle, #f8f9fa)',
      opacity: 0.5,
      pointerEvents: 'none',
      userSelect: 'none',
      position: 'relative',
    }}>
      <div style={{
        position: 'absolute', top: 8, left: 12,
        fontSize: 11, fontWeight: 700,
        color: 'var(--tp-text-muted, #6c757d)',
        textTransform: 'uppercase', letterSpacing: '0.06em',
      }}>
        <i className="bi bi-geo-alt me-1" />{d.label}
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = { intelCluster: IntelClusterNode, groupLabel: GroupLabelNode };
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
  { value: 'city', label: 'City' },
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
}

function ClusterPanel({ cluster, fileId, onClose }: ClusterPanelProps) {
  const navigate = useNavigate();
  const [convos, setConvos] = useState<Conversation[]>([]);
  const [convosLoading, setConvosLoading] = useState(false);
  type IpMetric = 'bytes' | 'conversations' | 'risks' | 'peers';
  const [ipMetric, setIpMetric] = useState<IpMetric>('bytes');

  // Escape is handled by the parent page (so it can respect fullscreen priority).

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
        position: 'fixed',
        top: '50%',
        right: 20,
        transform: 'translateY(-50%)',
        width: 300,
        zIndex: 1050,
        background: 'var(--tp-surface, #fff)',
        border: '1px solid var(--tp-border, #dee2e6)',
        borderRadius: 8,
        boxShadow: '0 4px 16px rgba(0,0,0,0.15)',
        fontSize: 13,
        display: 'flex',
        flexDirection: 'column',
        maxHeight: 'calc(100vh - 40px)',
      }}
    >
      <div className="d-flex justify-content-between align-items-start p-3 pb-2">
        <strong style={{ fontSize: 13 }}>
          {cluster.label}
          {(cluster.groupType === 'country' || cluster.groupType === 'city') && (
            <GeoSourceBadge source={cluster.geoSource} />
          )}
        </strong>
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
              <Badge key={p} className="bg-primary-subtle text-primary-emphasis" style={{ fontSize: 10 }}>{p}</Badge>
            ))}
          </div>
        )}

        {cluster.sampleIps.length > 0 && (
          <div className="mt-1">
            <div className="d-flex align-items-center justify-content-between mb-1">
              <small className="text-muted">Top hosts by</small>
              <Form.Select
                size="sm"
                style={{ width: 120, fontSize: 10, padding: '1px 4px' }}
                value={ipMetric}
                onChange={e => setIpMetric(e.target.value as IpMetric)}
              >
                <option value="bytes">Traffic</option>
                <option value="conversations">Conversations</option>
                <option value="risks">Risk flags</option>
                <option value="peers">Unique peers</option>
              </Form.Select>
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
          {convosLoading && <Spinner animation="border" size="sm" className="text-secondary" style={{ width: 12, height: 12, borderWidth: 2 }} />}
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
              <Button
                variant="outline-primary"
                size="sm"
                className="flex-shrink-0"
                style={{ fontSize: 10, padding: '2px 8px' }}
                onClick={() => navigate(`/analysis/${fileId}/conversations?highlight=${c.id}`)}
                title="View this conversation"
              >
                <i className="bi bi-arrow-right-circle me-1" />
                View
              </Button>
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
  onFilterClick?: () => void;
  activeFilterCount?: number;
  selectedCluster: ClusterNodeData | null;
  onSelectedClusterChange: (cluster: ClusterNodeData | null) => void;
}

const COLOR_MODE_OPTIONS: { value: ColorMode; label: string }[] = [
  { value: 'risk', label: 'Risk alerts' },
  { value: 'traffic', label: 'Traffic volume' },
];

export const ClusterGraph = ({ data, loading, groupBy, onGroupByChange, fileId, onFilterClick, activeFilterCount = 0, selectedCluster, onSelectedClusterChange }: ClusterGraphProps) => {
  const [rfNodes, setRfNodes] = useState<Node[]>([]);
  const [rfEdges, setRfEdges] = useState<Edge[]>([]);
  const [layoutLoading, setLayoutLoading] = useState(false);
  const [colorMode, setColorMode] = useState<ColorMode>('traffic');
  const [layoutVersion, setLayoutVersion] = useState(0);
  const layoutGen = useRef(0);

  const handleClusterPanelClose = useCallback(() => onSelectedClusterChange(null), [onSelectedClusterChange]);

  const clusterById = new Map((data?.clusters ?? []).map(c => [c.id, c]));

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    if (node.id.startsWith('__lane__')) return;
    const cluster = clusterById.get(node.id);
    onSelectedClusterChange(selectedCluster?.id === node.id ? null : (cluster ?? null));
  }, [data, selectedCluster, onSelectedClusterChange]); // eslint-disable-line react-hooks/exhaustive-deps

  // Let ReactFlow own node position/selection changes (enables dragging).
  const handleNodesChange: OnNodesChange = useCallback((changes) => {
    setRfNodes(prev => applyNodeChanges(changes, prev));
  }, []);

  useEffect(() => {
    if (!data || data.clusters.length === 0 || groupBy === 'country') {
      setRfNodes([]);
      setRfEdges([]);
      if (groupBy !== 'country') onSelectedClusterChange(null);
      return;
    }

    setLayoutLoading(true);

    const MAX_EDGE_BYTES = Math.max(...data.edges.map(e => e.totalBytes), 1);
    const MAX_NODE_BYTES = Math.max(...data.clusters.map(c => c.totalBytes), 1);

    const rawNodes: Node[] = data.clusters.map(c => ({
      id: c.id,
      type: 'intelCluster',
      position: { x: 0, y: 0 },
      draggable: true,
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

    const gen = ++layoutGen.current;
    runLayout(rawNodes, rawEdges, groupBy)
      .then(({ nodes, edges }) => {
        if (gen !== layoutGen.current) return;
        setRfNodes(nodes);
        setRfEdges(edges);
        setLayoutVersion(v => v + 1);
      })
      .catch(console.error)
      .finally(() => {
        if (gen === layoutGen.current) setLayoutLoading(false);
      });
  }, [data, groupBy]); // eslint-disable-line react-hooks/exhaustive-deps

  // Update colorMode on node data without re-running layout (preserves drag positions).
  // Also depends on layoutVersion so the current colorMode is re-applied after a layout
  // finishes (guards against a race where colorMode changed while ELK was still running).
  useEffect(() => {
    setRfNodes(prev => prev.map(n => n.id.startsWith('__lane__') ? n : ({
      ...n,
      data: { ...n.data, colorMode },
    })));
  }, [colorMode, layoutVersion]);

  // Update selected state on nodes without re-running layout
  useEffect(() => {
    setRfNodes(prev => prev.map(n => n.id.startsWith('__lane__') ? n : ({
      ...n,
      data: { ...n.data, selected: selectedCluster?.id === n.id },
    })));
  }, [selectedCluster]);

  return (
    <div className="intel-cluster-graph-wrapper">
      {/* Controls bar */}
      <div className="d-flex align-items-center gap-3 mb-3">
        <Form.Label className="mb-0 text-muted small">Group by</Form.Label>
        <Form.Select
          size="sm"
          style={{ width: 200 }}
          value={groupBy}
          onChange={e => onGroupByChange(e.target.value as GroupBy)}
          disabled={loading}
        >
          {GROUP_BY_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </Form.Select>

        <Form.Label className="mb-0 text-muted small ms-2">Color by</Form.Label>
        <Form.Select
          size="sm"
          style={{ width: 160 }}
          value={colorMode}
          onChange={e => setColorMode(e.target.value as ColorMode)}
        >
          {COLOR_MODE_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </Form.Select>

        {data && !loading && (
          <div className="d-flex align-items-center gap-2">
            <small className="text-muted">
              {data.clusters.length} cluster{data.clusters.length !== 1 ? 's' : ''},{' '}
              {data.edges.length} connection{data.edges.length !== 1 ? 's' : ''}
            </small>
            {data.hiddenClusters > 0 && (
              <Badge
                bg="secondary"
                style={{ fontSize: 10 }}
                title="Showing top clusters by traffic volume"
              >
                +{data.hiddenClusters} smaller hidden
              </Badge>
            )}
          </div>
        )}

        {(loading || layoutLoading) && (
          <Spinner animation="border" size="sm" className="text-primary" role="status" />
        )}
      </div>

      {/* Hint for Network Labels grouping */}
      {groupBy === 'customOrg' && (
        <Alert variant="info" className="py-2 mb-3 d-flex align-items-center gap-2" style={{ fontSize: 13 }}>
          <i className="bi bi-tag-fill flex-shrink-0" />
          <span>
            Network Labels are defined in{' '}
            <strong>Custom Detection Rules</strong> — open it from the navigation bar and go to the{' '}
            <strong>Network Labels</strong> tab to add or edit IP ranges.
          </span>
        </Alert>
      )}

      {/* Hint when geo-based grouping yields only internal traffic */}
      {data && !loading &&
        (groupBy === 'asn' || groupBy === 'country' || groupBy === 'city') &&
        data.clusters.length <= 2 &&
        data.clusters.every(c => c.label.startsWith('Internal')) && (
        <Alert variant="info" className="py-2 mb-3 d-flex align-items-center gap-2" style={{ fontSize: 13 }}>
          <i className="bi bi-info-circle-fill" />
          <span>
            All hosts are on an internal/private network — {groupBy === 'asn' ? 'ASN' : groupBy === 'country' ? 'Country' : 'City'} grouping
            has no external data to show. Try{' '}
            <strong>Subnet /24</strong> or <strong>Device Type</strong> for a meaningful view.
          </span>
          <Button size="sm" variant="info" className="ms-auto" onClick={() => onGroupByChange('subnet24')}>
            Switch to Subnet /24
          </Button>
        </Alert>
      )}

      {/* Node detail panel — rendered outside the graph canvas so it isn't
           clipped by overflow:hidden or affected by ReactFlow pane dragging.
           position:fixed anchors to the viewport. */}
      {selectedCluster && (
        <ClusterPanel
          cluster={selectedCluster}
          fileId={fileId}
          onClose={handleClusterPanelClose}
        />
      )}

      {/* Graph canvas */}
      {groupBy === 'country' ? (
        /* ── Country map view ── */
        <div className="intel-graph-container">
          {loading && (
            <div className="intel-graph-layouting">
              <Spinner animation="border" size="sm" />
              Loading…
            </div>
          )}

          {data && data.groupType === groupBy && (
            <CountryMapView
              data={data}
              colorMode={colorMode}
              selectedClusterId={selectedCluster?.id ?? null}
              onSelectCluster={c => onSelectedClusterChange(c)}
              fileId={fileId}
            />
          )}

          {onFilterClick && (
            <div className="intel-filter-overlay">
              <button className="ng-ctrl-btn position-relative" onClick={onFilterClick} title="Filters">
                <i className="bi bi-funnel" />
                {activeFilterCount > 0 && <span className="ng-filter-badge">{activeFilterCount}</span>}
              </button>
            </div>
          )}
        </div>
      ) : (
        /* ── ReactFlow graph view (all other groupBy strategies) ── */
        <div className="intel-graph-container">
          {(loading || layoutLoading) && (
            <div className="intel-graph-layouting">
              <Spinner animation="border" size="sm" />
              Computing layout…
            </div>
          )}

          {!loading && !layoutLoading && rfNodes.length === 0 ? (
            <div className="intel-graph-empty">
              <i className="bi bi-diagram-3 mb-2" style={{ fontSize: 32, opacity: 0.3 }} />
              <span>No cluster data available</span>
            </div>
          ) : (
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              onNodesChange={handleNodesChange}
              onNodeClick={handleNodeClick}
              fitView
              fitViewOptions={{ padding: 0.15 }}
              minZoom={0.1}
              maxZoom={3}
              nodesDraggable
              nodesConnectable={false}
              elementsSelectable
            >
              <Background color="#e9ecef" gap={20} />
              <Controls showInteractive={false} />
              <AutoFitView version={layoutVersion} />
            </ReactFlow>
          )}

          {onFilterClick && (
            <div className="intel-filter-overlay">
              <button className="ng-ctrl-btn position-relative" onClick={onFilterClick} title="Filters">
                <i className="bi bi-funnel" />
                {activeFilterCount > 0 && <span className="ng-filter-badge">{activeFilterCount}</span>}
              </button>
            </div>
          )}
        </div>
      )}

    </div>
  );
};
