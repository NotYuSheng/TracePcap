import { useState } from 'react';
import { Badge } from '@govtechsg/sgds-react';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { getProtocolColor } from '@/features/network/constants';
import { HostnameSourceBadge } from '@components/common/HostnameSourceBadge/HostnameSourceBadge';
import { Pagination } from '@components/common/Pagination/Pagination';
import { Alert } from '@components/common/Alert';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

const formatNumber = (num: number) => num.toLocaleString();

const PEERS_PAGE_SIZE = 15;

const GHOST_META: Record<string, { label: string; color: string }> = {
  'no-response':      { label: 'No response',      color: '#e74c3c' },
  'arp-no-reply':     { label: 'ARP no-reply',     color: '#e67e22' },
  'icmp-unreachable': { label: 'ICMP unreachable', color: '#c0392b' },
  'ttl-exceeded':     { label: 'TTL exceeded',     color: '#8e44ad' },
};

interface Props {
  node: GraphNode;
  edges: GraphEdge[];
  fileId: string;
  /** Open a peer IP in a nested modal. */
  onOpenPeer: (ip: string) => void;
  /** Navigate to a route (peer-row → conversations); the host routes and closes. */
  onNavigate?: (path: string) => void;
}

/**
 * The network-graph-only host detail — measured traffic counters, protocol chips, and the per-peer
 * Connections table (derived from graph edges). Extracted verbatim from the former standalone
 * NodeDetails so EntityDetailModal can host the same content when it is given graph context (#578).
 */
export function GraphNodeDetailsSection({ node, edges, fileId, onOpenPeer, onNavigate }: Props) {
  const [peersPage, setPeersPage] = useState(1);

  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id);

  // Per-peer summary: peerIp → { packets, bytes, apps }
  const peerMap = new Map<string, { packets: number; bytes: number; apps: Set<string> }>();
  connectedEdges.forEach(edge => {
    const peer = edge.source === node.id ? edge.target : edge.source;
    const existing = peerMap.get(peer) ?? { packets: 0, bytes: 0, apps: new Set() };
    existing.packets += edge.data.packetCount;
    existing.bytes += edge.data.totalBytes;
    existing.apps.add(edge.data.appName ?? edge.data.protocol);
    peerMap.set(peer, existing);
  });

  const peers = Array.from(peerMap.entries()).sort((a, b) => b[1].bytes - a[1].bytes);
  const peersTotalPages = Math.ceil(peers.length / PEERS_PAGE_SIZE);
  const peersPageClamped = Math.min(peersPage, Math.max(1, peersTotalPages));
  const visiblePeers = peers.slice(
    (peersPageClamped - 1) * PEERS_PAGE_SIZE,
    peersPageClamped * PEERS_PAGE_SIZE,
  );

  return (
    <>
      {/* Ghost node warning */}
      {node.data.ghostFlags && node.data.ghostFlags.length > 0 && (
        <Alert variant="warning" className="d-flex align-items-start gap-2 p-2 mb-3 small">
          <i className="bi bi-slash-circle mt-1 flex-shrink-0" aria-hidden="true" />
          <div>
            <span className="fw-semibold">Phantom node</span>
            <span className="ms-2">
              {node.data.ghostFlags.includes('arp-no-reply') && 'ARP request target — never replied.'}
              {node.data.ghostFlags.includes('ttl-exceeded') && 'Traceroute intermediate hop — only appeared via ICMP TTL-exceeded replies.'}
              {node.data.ghostFlags.includes('icmp-unreachable') && !node.data.ghostFlags.includes('arp-no-reply') && !node.data.ghostFlags.includes('ttl-exceeded') && 'ICMP probe target — never responded.'}
              {node.data.ghostFlags.includes('no-response') && !node.data.ghostFlags.includes('arp-no-reply') && !node.data.ghostFlags.includes('icmp-unreachable') && !node.data.ghostFlags.includes('ttl-exceeded') && 'Scan target — received traffic but never sent a reply.'}
            </span>
            <div className="mt-1 d-flex flex-wrap gap-1">
              {node.data.ghostFlags.map(flag => {
                const { label, color } = GHOST_META[flag] ?? { label: flag, color: '#6c757d' };
                return (
                  <span key={flag} className="badge" style={{ backgroundColor: color, color: '#fff', fontSize: '0.7rem' }}>
                    {label}
                  </span>
                );
              })}
            </div>
          </div>
        </Alert>
      )}

      {/* Identity + measured traffic counters */}
      <div className="row mb-3">
        <div className="col-sm-6">
          <dl className="row mb-0 small">
            <dt className="col-5 text-muted">IP</dt>
            <dd className="col-7 font-monospace mb-1">{node.data.ip}</dd>
            {node.data.mac && (
              <>
                <dt className="col-5 text-muted">MAC</dt>
                <dd className="col-7 font-monospace mb-1">{node.data.mac}</dd>
              </>
            )}
            {node.data.hostname && (
              <>
                <dt className="col-5 text-muted">Hostname</dt>
                <dd className="col-7 mb-1 d-flex align-items-center gap-1">
                  <span>{node.data.hostname}</span>
                  <HostnameSourceBadge source={node.data.hostnameSource} />
                </dd>
              </>
            )}
          </dl>
        </div>
        <div className="col-sm-6">
          <dl className="row mb-0 small">
            <dt className="col-7 text-muted">Packets sent</dt>
            <dd className="col-5 mb-1">{formatNumber(node.data.packetsSent)}</dd>
            <dt className="col-7 text-muted">Packets received</dt>
            <dd className="col-5 mb-1">{formatNumber(node.data.packetsReceived)}</dd>
            <dt className="col-7 text-muted">Bytes sent</dt>
            <dd className="col-5 mb-1">{formatBytes(node.data.bytesSent)}</dd>
            <dt className="col-7 text-muted">Bytes received</dt>
            <dd className="col-5 mb-1">{formatBytes(node.data.bytesReceived)}</dd>
            <dt className="col-7 text-muted fw-bold">Total bytes</dt>
            <dd className="col-5 mb-1 fw-bold">{formatBytes(node.data.totalBytes)}</dd>
          </dl>
        </div>
      </div>

      {/* Protocols */}
      <div className="mb-3">
        <h6 className="border-bottom pb-1 mb-2">Protocols</h6>
        <div className="d-flex flex-wrap gap-1">
          {node.data.protocols.map(p => (
            <span key={p} className="badge" style={{ backgroundColor: getProtocolColor(p), color: '#fff' }}>
              {p}
            </span>
          ))}
        </div>
      </div>

      {/* Connections table */}
      <div>
        <h6 className="border-bottom pb-1 mb-2">
          Connections ({peers.length} peer{peers.length !== 1 ? 's' : ''})
        </h6>
        <div className="table-responsive rounded border overflow-hidden">
          <table className="table table-sm table-hover mb-0">
            <thead className="table-light" style={{ fontSize: '0.8rem' }}>
              <tr>
                <th>Peer IP</th>
                <th>Application / Protocol</th>
                <th className="text-end">Packets</th>
                <th className="text-end">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {visiblePeers.map(([ip, info]) => (
                <tr
                  key={ip}
                  className="node-details-peer-row"
                  title="Click to view conversations"
                  onClick={() =>
                    onNavigate?.(`/analysis/${fileId}/conversations?srcIp=${node.data.ip}&peerIp=${ip}`)
                  }
                >
                  <td className="font-monospace small">
                    <button
                      className="btn btn-link btn-sm p-0 font-monospace text-start"
                      style={{ fontSize: 'inherit' }}
                      onClick={e => { e.stopPropagation(); onOpenPeer(ip); }}
                    >
                      {ip}
                    </button>
                    <i className="bi bi-arrow-right-circle ms-1 text-muted node-details-peer-icon" aria-hidden="true"></i>
                  </td>
                  <td>
                    {Array.from(info.apps).map(app => (
                      <Badge key={app} bg="light" text="dark" className="me-1 border">{app}</Badge>
                    ))}
                  </td>
                  <td className="text-end small">{formatNumber(info.packets)}</td>
                  <td className="text-end small">{formatBytes(info.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {peersTotalPages > 1 && (
          <Pagination
            currentPage={peersPageClamped}
            totalPages={peersTotalPages}
            totalItems={peers.length}
            pageSize={PEERS_PAGE_SIZE}
            onPageChange={setPeersPage}
            showPageSizeSelector={false}
          />
        )}
      </div>
    </>
  );
}
