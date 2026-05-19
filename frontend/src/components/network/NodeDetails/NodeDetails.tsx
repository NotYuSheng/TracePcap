import { useEffect, useState } from 'react';
import { Badge } from '@govtechsg/sgds-react';
import { useNavigate } from 'react-router-dom';
import type { GraphNode, GraphEdge } from '@/features/network/types';
import { NODE_TYPE_CONFIG, getProtocolColor } from '@/features/network/constants';
import { deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';
import { NodeClassificationPopup } from '@components/common/NodeClassificationPopup/NodeClassificationPopup';
import type { NodeHighlight } from '@/components/network/NetworkGraph/NetworkGraph';
import './NodeDetails.css';

interface NodeDetailsProps {
  node: GraphNode;
  edges: GraphEdge[];
  fileId: string;
  onClose: () => void;
  changeHighlight?: NodeHighlight;
  zIndex?: number;
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
    case 'client':
      return 'bg-primary';
    case 'server':
      return 'bg-success';
    case 'both':
      return 'bg-secondary';
    default:
      return 'bg-light text-dark';
  }
}


export function NodeDetails({ node, edges, fileId, onClose, changeHighlight, zIndex }: NodeDetailsProps) {
  const navigate = useNavigate();
  const [classificationPopupOpen, setClassificationPopupOpen] = useState(false);

  // ESC closes the modal — stop propagation so parent modals don't also close
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopImmediatePropagation();
        onClose();
      }
    };
    document.addEventListener('keydown', onKeyDown, { capture: true });
    return () => document.removeEventListener('keydown', onKeyDown, { capture: true });
  }, [onClose]);

  // Lock background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id);
  const initiatedCount = connectedEdges.filter(e => e.source === node.id).length;
  const receivedCount = connectedEdges.filter(e => e.target === node.id).length;

  // Build per-peer summary: peerIp → { packets, bytes, apps }
  const peerMap = new Map<string, { packets: number; bytes: number; apps: Set<string> }>();
  connectedEdges.forEach(edge => {
    const peer = edge.source === node.id ? edge.target : edge.source;
    const existing = peerMap.get(peer) ?? { packets: 0, bytes: 0, apps: new Set() };
    existing.packets += edge.data.packetCount;
    existing.bytes += edge.data.totalBytes;
    const label = edge.data.appName ?? edge.data.protocol;
    existing.apps.add(label);
    peerMap.set(peer, existing);
  });

  const peers = Array.from(peerMap.entries()).sort((a, b) => b[1].bytes - a[1].bytes);

  const typeInfo = NODE_TYPE_CONFIG[node.data.nodeType] ?? NODE_TYPE_CONFIG['unknown'];
  return (
    <div
      className="modal fade show d-block"
      style={{ backgroundColor: 'rgba(0,0,0,0.5)', zIndex: zIndex ?? 1055 }}
      onClick={e => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="node-details-title"
    >
      <div className="modal-dialog modal-lg modal-dialog-scrollable">
        <div className="modal-content">
          <div className="modal-header">
            <h5 id="node-details-title" className="modal-title font-monospace">
              {node.data.ip}
              {node.data.hostname && (
                <small className="text-muted ms-2 fw-normal node-details-hostname">
                  ({node.data.hostname})
                </small>
              )}
            </h5>
            <button
              type="button"
              className="btn-close ms-3"
              onClick={onClose}
              title="Close (Esc)"
            />
          </div>

          <div className="modal-body">
            {/* Change event highlight banner */}
            {changeHighlight && (
              <div
                className="d-flex align-items-center gap-2 rounded p-2 mb-3 small"
                style={{ background: changeHighlight.color + '22', border: `1px solid ${changeHighlight.color}55` }}
              >
                <span
                  style={{ width: 10, height: 10, borderRadius: '50%', background: changeHighlight.color, flexShrink: 0, display: 'inline-block' }}
                />
                <span style={{ color: changeHighlight.color, fontWeight: 600 }}>
                  {changeHighlight.label}
                </span>
                {changeHighlight.description && (
                  <span className="text-muted">— {changeHighlight.description}</span>
                )}
              </div>
            )}

            {/* Identity */}
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
                      <dd className="col-7 mb-1">{node.data.hostname}</dd>
                    </>
                  )}

                  <dt className="col-5 text-muted">Classification</dt>
                  <dd className="col-7 mb-1">
                    {(() => {
                      // Pick the single most informative badge label + style
                      const isGeneric =
                        node.data.nodeType === 'client' || node.data.nodeType === 'unknown';
                      let badgeContent: React.ReactNode;
                      if (!isGeneric) {
                        // Specific type is the clearest signal
                        badgeContent = (
                          <span className={`badge ${typeInfo.badgeClass}`}>{typeInfo.label}</span>
                        );
                      } else if (node.data.deviceType) {
                        // Device type is more informative than "client/unknown"
                        badgeContent = (
                          <span
                            className="badge"
                            style={{
                              backgroundColor: deviceTypeColor(node.data.deviceType),
                              color: '#fff',
                            }}
                          >
                            {deviceTypeLabel(node.data.deviceType)}
                          </span>
                        );
                      } else {
                        // Fall back to role
                        badgeContent = (
                          <span className={`badge ${getRoleBadgeClass(node.data.role)}`}>
                            {node.data.role.charAt(0).toUpperCase() + node.data.role.slice(1)}
                          </span>
                        );
                      }
                      return (
                        <span
                          role="button"
                          title="Click for classification details"
                          style={{ cursor: 'pointer' }}
                          onClick={e => {
                            e.stopPropagation();
                            setClassificationPopupOpen(true);
                          }}
                        >
                          {badgeContent}
                        </span>
                      );
                    })()}
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

            {/* Protocols */}
            <div className="mb-3">
              <h6 className="border-bottom pb-1 mb-2">Protocols</h6>
              <div className="d-flex flex-wrap gap-1">
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
                            <Badge key={app} bg="light" text="dark" className="me-1 border">
                              {app}
                            </Badge>
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

      {classificationPopupOpen && (
        <NodeClassificationPopup
          info={{
            ip: node.data.ip,
            nodeType: node.data.nodeType,
            typeLabel: typeInfo.label,
            typeBadgeClass: typeInfo.badgeClass,
            typeEvidence: node.data.nodeTypeEvidence,
            role: node.data.role,
            initiated: initiatedCount,
            received: receivedCount,
            deviceType: node.data.deviceType,
            deviceConfidence: node.data.deviceConfidence,
            manufacturer: node.data.manufacturer,
            ttl: node.data.ttl,
          }}
          onClose={() => setClassificationPopupOpen(false)}
        />
      )}
    </div>
  );
}
