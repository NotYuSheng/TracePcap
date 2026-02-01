import type { GraphNode, GraphEdge } from '@/features/network/types'
import './NodeDetails.css'

interface NodeDetailsProps {
  node: GraphNode
  edges: GraphEdge[]
  onClose: () => void
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

/**
 * Format number with commas
 */
function formatNumber(num: number): string {
  return num.toLocaleString()
}

/**
 * Get role badge class
 */
function getRoleBadgeClass(role: string): string {
  switch (role) {
    case 'client':
      return 'bg-primary'
    case 'server':
      return 'bg-success'
    case 'both':
      return 'bg-secondary'
    default:
      return 'bg-light text-dark'
  }
}

export function NodeDetails({ node, edges, onClose }: NodeDetailsProps) {
  // Find all edges connected to this node
  const connectedEdges = edges.filter(
    (edge) => edge.source === node.id || edge.target === node.id
  )

  // Get unique connected nodes
  const connectedNodes = new Set<string>()
  const connectionsByProtocol: { [protocol: string]: number } = {}

  connectedEdges.forEach((edge) => {
    const otherNode = edge.source === node.id ? edge.target : edge.source
    connectedNodes.add(otherNode)

    const protocol = edge.data.protocol
    connectionsByProtocol[protocol] =
      (connectionsByProtocol[protocol] || 0) + 1
  })

  return (
    <div className="node-details-panel">
      <div className="card">
        <div className="card-header d-flex justify-content-between align-items-center">
          <h6 className="mb-0">
            <i className="bi bi-hdd-network me-2"></i>
            Node Details
          </h6>
          <button
            type="button"
            className="btn-close btn-sm"
            onClick={onClose}
            aria-label="Close"
          ></button>
        </div>
        <div className="card-body">
          {/* Node Identity */}
          <div className="mb-3">
            <div className="d-flex justify-content-between align-items-start mb-2">
              <div>
                <div className="text-muted small">IP Address</div>
                <div className="fw-bold">{node.data.ip}</div>
              </div>
              <span className={`badge ${getRoleBadgeClass(node.data.role)}`}>
                {node.data.role.toUpperCase()}
              </span>
            </div>
            {node.data.mac && (
              <div className="mb-2">
                <div className="text-muted small">MAC Address</div>
                <div className="text-monospace">{node.data.mac}</div>
              </div>
            )}
            {node.data.hostname && (
              <div className="mb-2">
                <div className="text-muted small">Hostname</div>
                <div>{node.data.hostname}</div>
              </div>
            )}
            {node.data.isAnomaly && (
              <div className="alert alert-danger py-2 px-2 mb-2">
                <i className="bi bi-exclamation-triangle me-2"></i>
                <small><strong>Anomaly Detected</strong></small>
              </div>
            )}
          </div>

          {/* Traffic Statistics */}
          <div className="mb-3">
            <h6 className="border-bottom pb-2 mb-2">Traffic Statistics</h6>
            <div className="stats-table">
              <div className="stats-row">
                <span className="stats-label">
                  <i className="bi bi-arrow-up-circle text-primary me-1"></i>
                  Packets Sent
                </span>
                <span className="stats-value">
                  {formatNumber(node.data.packetsSent)}
                </span>
              </div>
              <div className="stats-row">
                <span className="stats-label">
                  <i className="bi bi-arrow-down-circle text-success me-1"></i>
                  Packets Received
                </span>
                <span className="stats-value">
                  {formatNumber(node.data.packetsReceived)}
                </span>
              </div>
              <div className="stats-row">
                <span className="stats-label">
                  <i className="bi bi-hdd text-info me-1"></i>
                  Bytes Sent
                </span>
                <span className="stats-value">
                  {formatBytes(node.data.bytesSent)}
                </span>
              </div>
              <div className="stats-row">
                <span className="stats-label">
                  <i className="bi bi-hdd-fill text-warning me-1"></i>
                  Bytes Received
                </span>
                <span className="stats-value">
                  {formatBytes(node.data.bytesReceived)}
                </span>
              </div>
              <div className="stats-row border-top pt-2">
                <span className="stats-label fw-bold">Total Bytes</span>
                <span className="stats-value fw-bold">
                  {formatBytes(node.data.totalBytes)}
                </span>
              </div>
            </div>
          </div>

          {/* Protocols Used */}
          <div className="mb-3">
            <h6 className="border-bottom pb-2 mb-2">Protocols Used</h6>
            <div className="d-flex flex-wrap gap-1">
              {node.data.protocols.map((protocol) => (
                <span key={protocol} className="badge bg-secondary">
                  {protocol}
                </span>
              ))}
            </div>
          </div>

          {/* Connections */}
          <div className="mb-3">
            <h6 className="border-bottom pb-2 mb-2">
              Connections ({connectedNodes.size})
            </h6>
            <div className="connections-list">
              {Array.from(connectedNodes).map((ip) => (
                <div key={ip} className="connection-item">
                  <i className="bi bi-link-45deg me-2 text-muted"></i>
                  <span className="text-monospace">{ip}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Connections by Protocol */}
          <div>
            <h6 className="border-bottom pb-2 mb-2">Connections by Protocol</h6>
            <div className="protocol-breakdown">
              {Object.entries(connectionsByProtocol).map(
                ([protocol, count]) => (
                  <div key={protocol} className="protocol-row">
                    <span className="protocol-name">{protocol}</span>
                    <span className="badge bg-light text-dark">{count}</span>
                  </div>
                )
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
