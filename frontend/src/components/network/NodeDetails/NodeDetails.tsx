import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import type { GraphNode, GraphEdge, NodeType } from '@/features/network/types';
import './NodeDetails.css';

interface NodeDetailsProps {
  node: GraphNode;
  edges: GraphEdge[];
  fileId: string;
  onClose: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

function formatNumber(num: number): string {
  return num.toLocaleString();
}

function getRoleBadgeClass(role: string): string {
  switch (role) {
    case 'client': return 'bg-primary';
    case 'server': return 'bg-success';
    case 'both':   return 'bg-secondary';
    default:       return 'bg-light text-dark';
  }
}

const NODE_TYPE_DISPLAY: Record<NodeType, { label: string; icon: string; badgeClass: string }> = {
  'dns-server':      { label: 'DNS Server',      icon: 'bi-globe2',          badgeClass: 'bg-warning text-dark' },
  'web-server':      { label: 'Web Server',       icon: 'bi-server',          badgeClass: 'bg-success' },
  'ssh-server':      { label: 'SSH Server',       icon: 'bi-terminal',        badgeClass: 'bg-info text-dark' },
  'ftp-server':      { label: 'FTP Server',       icon: 'bi-folder-symlink',  badgeClass: 'bg-secondary' },
  'mail-server':     { label: 'Mail Server',      icon: 'bi-envelope',        badgeClass: 'bg-danger' },
  'dhcp-server':     { label: 'DHCP Server',      icon: 'bi-diagram-3',       badgeClass: 'bg-secondary' },
  'ntp-server':      { label: 'NTP Server',       icon: 'bi-clock',           badgeClass: 'bg-dark' },
  'database-server': { label: 'Database Server',  icon: 'bi-database',        badgeClass: 'bg-danger' },
  'router':          { label: 'Router / Gateway', icon: 'bi-router',          badgeClass: 'bg-warning text-dark' },
  'client':          { label: 'Client',           icon: 'bi-laptop',          badgeClass: 'bg-primary' },
  'unknown':         { label: 'Unknown',          icon: 'bi-question-circle', badgeClass: 'bg-light text-dark' },
};

export function NodeDetails({ node, edges, fileId, onClose }: NodeDetailsProps) {
  const navigate = useNavigate();
  // ESC closes the modal
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  // Lock background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id);

  // Build per-peer summary: peerIp → { packets, bytes, apps }
  const peerMap = new Map<string, { packets: number; bytes: number; apps: Set<string> }>();
  connectedEdges.forEach(edge => {
    const peer = edge.source === node.id ? edge.target : edge.source;
    const existing = peerMap.get(peer) ?? { packets: 0, bytes: 0, apps: new Set() };
    existing.packets += edge.data.packetCount;
    existing.bytes   += edge.data.totalBytes;
    const label = edge.data.appName ?? edge.data.protocol;
    existing.apps.add(label);
    peerMap.set(peer, existing);
  });

  const peers = Array.from(peerMap.entries()).sort((a, b) => b[1].bytes - a[1].bytes);

  const typeInfo = NODE_TYPE_DISPLAY[node.data.nodeType] ?? NODE_TYPE_DISPLAY['unknown'];
  const ev = node.data.nodeTypeEvidence;

  return (
    <div
      className="modal fade show d-block"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="node-details-title"
    >
      <div className="modal-dialog modal-lg modal-dialog-scrollable">
        <div className="modal-content">

          <div className="modal-header">
            <h5 id="node-details-title" className="modal-title font-monospace">
              <i className={`bi ${typeInfo.icon} me-2`}></i>
              {node.data.ip}
              {node.data.hostname && (
                <small className="text-muted ms-2 fw-normal node-details-hostname">
                  ({node.data.hostname})
                </small>
              )}
            </h5>
            <button type="button" className="btn-close ms-3" onClick={onClose} title="Close (Esc)" />
          </div>

          <div className="modal-body">
            {/* Identity */}
            <div className="row mb-3">
              <div className="col-sm-6">
                <dl className="row mb-0 small">
                  <dt className="col-5 text-muted">IP</dt>
                  <dd className="col-7 font-monospace mb-1">{node.data.ip}</dd>

                  {node.data.mac && <>
                    <dt className="col-5 text-muted">MAC</dt>
                    <dd className="col-7 font-monospace mb-1">{node.data.mac}</dd>
                  </>}

                  {node.data.hostname && <>
                    <dt className="col-5 text-muted">Hostname</dt>
                    <dd className="col-7 mb-1">{node.data.hostname}</dd>
                  </>}

                  <dt className="col-5 text-muted">Role</dt>
                  <dd className="col-7 mb-1">
                    <span className={`badge ${getRoleBadgeClass(node.data.role)}`}>
                      {node.data.role.toUpperCase()}
                    </span>
                  </dd>

                  <dt className="col-5 text-muted">Type</dt>
                  <dd className="col-7 mb-1">
                    <span className={`badge ${typeInfo.badgeClass}`}>
                      <i className={`bi ${typeInfo.icon} me-1`}></i>
                      {typeInfo.label}
                    </span>
                    {ev.dominantPort && (
                      <div className="text-muted mt-1 node-details-evidence">
                        {ev.connectionCount} conn. on port {ev.dominantPort}
                      </div>
                    )}
                    {!ev.dominantPort && node.data.nodeType === 'router' && (
                      <div className="text-muted mt-1 node-details-evidence">
                        {ev.distinctPeers} distinct peers
                      </div>
                    )}
                  </dd>
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

            {node.data.isAnomaly && (
              <div className="alert alert-danger py-2 mb-3">
                <i className="bi bi-exclamation-triangle me-2"></i>
                <strong>Anomaly Detected</strong>
              </div>
            )}

            {/* Protocols */}
            <div className="mb-3">
              <h6 className="border-bottom pb-1 mb-2">Protocols</h6>
              <div className="d-flex flex-wrap gap-1">
                {node.data.protocols.map(p => (
                  <span key={p} className="badge bg-secondary">{p}</span>
                ))}
              </div>
            </div>

            {/* Connections table */}
            <div>
              <h6 className="border-bottom pb-1 mb-2">
                Connections ({peers.length} peer{peers.length !== 1 ? 's' : ''})
              </h6>
              <div className="table-responsive">
                <table className="table table-sm table-hover mb-0">
                  <thead className="table-light">
                    <tr>
                      <th>Peer IP</th>
                      <th>Application / Protocol</th>
                      <th className="text-end">Packets</th>
                      <th className="text-end">Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {peers.map(([ip, info]) => (
                      <tr
                        key={ip}
                        className="node-details-peer-row"
                        title="Click to view conversations"
                        onClick={() => {
                          onClose();
                          navigate(
                            `/analysis/${fileId}/conversations?srcIp=${node.data.ip}&peerIp=${ip}`
                          );
                        }}
                      >
                        <td className="font-monospace small">
                          {ip}
                          <i className="bi bi-arrow-right-circle ms-1 text-muted node-details-peer-icon"></i>
                        </td>
                        <td>
                          {Array.from(info.apps).map(app => (
                            <span key={app} className="badge bg-light text-dark me-1 border">{app}</span>
                          ))}
                        </td>
                        <td className="text-end small">{formatNumber(info.packets)}</td>
                        <td className="text-end small">{formatBytes(info.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
