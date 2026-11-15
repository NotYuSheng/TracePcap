import { useState } from 'react';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { getProtocolColor } from '@/features/network/constants';
import { Pagination } from '@components/common/Pagination/Pagination';
import { WindowsLogonTimeline } from '@components/common/WindowsLogonTimeline';
import { Alert } from '@components/common/Alert';
import { formatBytes, formatNumber } from '../format';

const PEERS_PAGE_SIZE = 15;

/**
 * Human-readable phantom-node explanations, joined with a space (the icmp/no-response messages are
 * mutually exclusive with the more specific arp/ttl ones, mirroring the original precedence).
 */
function ghostMessages(flags: string[]): string[] {
  const msgs: string[] = [];
  if (flags.includes('arp-no-reply')) msgs.push('ARP request target — never replied.');
  if (flags.includes('ttl-exceeded'))
    msgs.push('Traceroute intermediate hop — only appeared via ICMP TTL-exceeded replies.');
  if (
    flags.includes('icmp-unreachable') &&
    !flags.includes('arp-no-reply') &&
    !flags.includes('ttl-exceeded')
  ) {
    msgs.push('ICMP probe target — never responded.');
  }
  if (
    flags.includes('no-response') &&
    !flags.includes('arp-no-reply') &&
    !flags.includes('icmp-unreachable') &&
    !flags.includes('ttl-exceeded')
  ) {
    msgs.push('Scan target — received traffic but never sent a reply.');
  }
  return msgs;
}

const GHOST_META: Record<string, { label: string; color: string }> = {
  'no-response': { label: 'No response', color: '#e74c3c' },
  'arp-no-reply': { label: 'ARP no-reply', color: '#e67e22' },
  'icmp-unreachable': { label: 'ICMP unreachable', color: '#c0392b' },
  'ttl-exceeded': { label: 'TTL exceeded', color: '#8e44ad' },
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
 * The node dialog's Traffic tab: measured counters, protocol chips, and who it talked to (derived
 * from graph edges), each peer with a bar for its share. Who the host is lives in GraphNodeIdentityCard.
 */
export function GraphNodeDetailsSection({ node, edges, fileId, onOpenPeer, onNavigate }: Props) {
  const [peersPage, setPeersPage] = useState(1);

  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id);

  // Per-peer summary: peerIp → { packets, bytes, apps }
  const peerMap = new Map<string, { packets: number; bytes: number; apps: Set<string> }>();
  connectedEdges.forEach(edge => {
    // A device on a reused address has the id `ip@idx` (#918 slice 2); the peer is still the address.
    const peer = (edge.source === node.id ? edge.target : edge.source).replace(/@\d+$/, '');
    const existing = peerMap.get(peer) ?? { packets: 0, bytes: 0, apps: new Set() };
    existing.packets += edge.data.packetCount;
    existing.bytes += edge.data.totalBytes;
    existing.apps.add(edge.data.appName ?? edge.data.protocol);
    peerMap.set(peer, existing);
  });

  const peers = Array.from(peerMap.entries()).sort((a, b) => b[1].bytes - a[1].bytes);
  const maxBytes = Math.max(1, ...peers.map(([, p]) => p.bytes));
  const peersTotalPages = Math.ceil(peers.length / PEERS_PAGE_SIZE);
  const peersPageClamped = Math.min(peersPage, Math.max(1, peersTotalPages));
  const visiblePeers = peers.slice(
    (peersPageClamped - 1) * PEERS_PAGE_SIZE,
    peersPageClamped * PEERS_PAGE_SIZE
  );

  return (
    <>
      {/* Ghost node warning */}
      {node.data.ghostFlags && node.data.ghostFlags.length > 0 && (
        <Alert variant="warning" className="d-flex align-items-start gap-2 p-2 mb-3 small">
          <i className="bi bi-slash-circle mt-1 flex-shrink-0" aria-hidden="true" />
          <div>
            <span className="fw-semibold">Phantom node</span>
            <span className="ms-2">{ghostMessages(node.data.ghostFlags).join(' ')}</span>
            <div className="mt-1 d-flex flex-wrap gap-1">
              {node.data.ghostFlags.map(flag => {
                const { label, color } = GHOST_META[flag] ?? { label: flag, color: '#6c757d' };
                return (
                  <span
                    key={flag}
                    className="badge"
                    style={{ backgroundColor: color, color: '#fff', fontSize: '0.7rem' }}
                  >
                    {label}
                  </span>
                );
              })}
            </div>
          </div>
        </Alert>
      )}

      {/* Measured traffic counters. Who the host is sits in the identity card beside this. */}
      <div className="node-stats mb-3" data-testid="node-stats">
        <div className="node-stat">
          <div className="node-stat-value">{formatNumber(node.data.packetsSent)}</div>
          <div className="node-stat-label">packets sent</div>
        </div>
        <div className="node-stat">
          <div className="node-stat-value">{formatNumber(node.data.packetsReceived)}</div>
          <div className="node-stat-label">received</div>
        </div>
        <div className="node-stat">
          <div className="node-stat-value">{formatBytes(node.data.totalBytes)}</div>
          <div className="node-stat-label">in total</div>
          <div className="node-stat-sub">
            {formatBytes(node.data.bytesSent)} out · {formatBytes(node.data.bytesReceived)} in
          </div>
        </div>
        <div className="node-stat">
          <div className="node-stat-value">{formatNumber(peers.length)}</div>
          <div className="node-stat-label">peer{peers.length !== 1 ? 's' : ''}</div>
        </div>
      </div>

      <WindowsLogonTimeline fileId={fileId} ip={node.data.ip} deviceType={node.data.deviceType} />

      {/* Protocols */}
      <div className="d-flex flex-wrap align-items-center gap-1 mb-3 small">
        <span className="text-muted me-1">Protocols</span>
        {node.data.protocols.map(p => (
          <span
            key={p}
            className="badge"
            style={{ backgroundColor: getProtocolColor(p), color: '#fff' }}
          >
            {p}
          </span>
        ))}
      </div>

      {/* Who it talked to, biggest first, each bar scaled to the biggest peer. */}
      <div>
        <h6 className="mb-2">
          Peers <span className="text-muted fw-normal small">· click an address to inspect it</span>
        </h6>
        <div className="table-responsive">
          <table className="table table-sm mb-0 small align-middle node-peers">
            <thead>
              <tr>
                <th scope="col">Peer</th>
                <th scope="col">App</th>
                <th scope="col" className="node-peers-traffic">
                  Traffic
                </th>
                <th scope="col" className="text-end">
                  Packets
                </th>
                <th scope="col">
                  <span className="visually-hidden">Conversations</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {visiblePeers.map(([ip, info]) => (
                <tr key={ip}>
                  <td>
                    <button
                      type="button"
                      className="btn btn-link btn-sm p-0 font-monospace text-start"
                      style={{ fontSize: 'inherit' }}
                      onClick={() => onOpenPeer(ip)}
                    >
                      {ip}
                    </button>
                  </td>
                  <td className="text-muted">{Array.from(info.apps).join(', ')}</td>
                  <td>
                    <div className="node-peer-bar-row">
                      <div className="node-peer-bar" aria-hidden="true">
                        <div
                          className="node-peer-bar-fill"
                          style={{ width: `${Math.max(2, (info.bytes / maxBytes) * 100)}%` }}
                        />
                      </div>
                      <span className="node-peer-bytes">{formatBytes(info.bytes)}</span>
                    </div>
                  </td>
                  <td className="text-end text-muted">{formatNumber(info.packets)}</td>
                  <td className="text-end">
                    <button
                      type="button"
                      className="btn btn-link btn-sm p-0"
                      aria-label={`Conversations with ${ip}`}
                      onClick={() =>
                        onNavigate?.(
                          `/analysis/${fileId}/conversations?srcIp=${node.data.ip}&peerIp=${ip}`
                        )
                      }
                    >
                      <i className="bi bi-arrow-right-circle" aria-hidden="true" />
                    </button>
                  </td>
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
