import type { NetworkStats } from '@/features/network/types';
import './NetworkControls.css';

interface NetworkControlsProps {
  stats: NetworkStats;
  layoutType: 'forceDirected2d' | 'hierarchicalTd';
  onLayoutChange: (layout: 'forceDirected2d' | 'hierarchicalTd') => void;
  activeLegendProtocol: string | null;
  onLegendProtocolClick: (key: string | null) => void;
  activeLegendNodeType: string | null;
  onLegendNodeTypeClick: (key: string | null) => void;
  presentNodeTypes: Set<string>;
  presentEdgeLegendKeys: Set<string>;
}

const EDGE_LEGEND = [
  { label: 'HTTP',      key: 'HTTP',  color: '#2ecc71' },
  { label: 'HTTPS/TLS', key: 'HTTPS', color: '#3498db' },
  { label: 'DNS',       key: 'DNS',   color: '#f39c12' },
  { label: 'TCP',       key: 'TCP',   color: '#7f8c8d' },
  { label: 'UDP',       key: 'UDP',   color: '#f1c40f' },
];

const NODE_LEGEND = [
  { label: 'DNS Server',      key: 'dns-server',      color: '#f39c12' },
  { label: 'Web Server',      key: 'web-server',      color: '#2ecc71' },
  { label: 'SSH Server',      key: 'ssh-server',      color: '#1abc9c' },
  { label: 'FTP Server',      key: 'ftp-server',      color: '#16a085' },
  { label: 'Mail Server',     key: 'mail-server',     color: '#e91e63' },
  { label: 'DHCP Server',     key: 'dhcp-server',     color: '#8e44ad' },
  { label: 'NTP Server',      key: 'ntp-server',      color: '#6c3483' },
  { label: 'Database Server', key: 'database-server', color: '#e67e22' },
  { label: 'Router / Gateway',key: 'router',          color: '#d4ac0d' },
  { label: 'Client',          key: 'client',          color: '#3498db' },
  { label: 'Anomaly',         key: 'anomaly',         color: '#e74c3c' },
  { label: 'Unknown',         key: 'unknown',         color: '#95a5a6' },
];

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

/**
 * Format number with commas
 */
function formatNumber(num: number): string {
  return num.toLocaleString();
}

export function NetworkControls({
  stats,
  layoutType,
  onLayoutChange,
  activeLegendProtocol,
  onLegendProtocolClick,
  activeLegendNodeType,
  onLegendNodeTypeClick,
  presentNodeTypes,
  presentEdgeLegendKeys,
}: NetworkControlsProps) {

  return (
    <div className="network-controls">
      <h6 className="mb-3">
        <i className="bi bi-sliders me-2"></i>
        Network Controls
      </h6>

      {/* Statistics Summary */}
      <div className="card mb-3">
        <div className="card-header">
          <strong>Network Statistics</strong>
        </div>
        <div className="card-body p-2">
          <div className="stats-grid">
            <div className="stat-item">
              <div className="stat-label">Nodes</div>
              <div className="stat-value">{formatNumber(stats.totalNodes)}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Connections</div>
              <div className="stat-value">{formatNumber(stats.totalEdges)}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Packets</div>
              <div className="stat-value">{formatNumber(stats.totalPackets)}</div>
            </div>
            <div className="stat-item">
              <div className="stat-label">Data</div>
              <div className="stat-value">{formatBytes(stats.totalBytes)}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Layout Control */}
      <div className="mb-3">
        <label className="form-label">
          <strong>Layout</strong>
        </label>
        <div className="btn-group d-flex" role="group">
          <button
            type="button"
            className={`btn btn-sm ${
              layoutType === 'forceDirected2d' ? 'btn-primary' : 'btn-outline-primary'
            }`}
            onClick={() => onLayoutChange('forceDirected2d')}
          >
            Force Directed
          </button>
          <button
            type="button"
            className={`btn btn-sm ${
              layoutType === 'hierarchicalTd' ? 'btn-primary' : 'btn-outline-primary'
            }`}
            onClick={() => onLayoutChange('hierarchicalTd')}
          >
            Hierarchical
          </button>
        </div>
      </div>


      {/* Legend */}
      <div className="card">
        <div className="card-header">
          <strong>Legend</strong>
        </div>
        <div className="card-body p-2">
          <div className="legend-section mb-2">
            <div className="legend-title d-flex justify-content-between align-items-center">
              <span>Node Types</span>
              {activeLegendNodeType && (
                <button
                  className="btn btn-link btn-sm p-0 text-muted"
                  style={{ fontSize: '0.7rem' }}
                  onClick={() => onLegendNodeTypeClick(null)}
                >
                  Clear filter ×
                </button>
              )}
            </div>
            <small className="text-muted d-block mb-1" style={{ fontSize: '0.7rem' }}>
              Click to isolate
            </small>
            {NODE_LEGEND.filter(({ key }) => presentNodeTypes.has(key)).map(({ label, key, color }) => (
              <button
                key={key}
                className={`legend-item-btn ${activeLegendNodeType === key ? 'active' : ''} ${activeLegendNodeType && activeLegendNodeType !== key ? 'dimmed' : ''}`}
                onClick={() => onLegendNodeTypeClick(activeLegendNodeType === key ? null : key)}
                title={`Show only ${label} nodes and their connections`}
              >
                <span className="legend-color" style={{ background: color }}></span>
                {label}
              </button>
            ))}
          </div>
          <div className="legend-section">
            <div className="legend-title d-flex justify-content-between align-items-center">
              <span>Edge Protocols</span>
              {activeLegendProtocol && (
                <button
                  className="btn btn-link btn-sm p-0 text-muted"
                  style={{ fontSize: '0.7rem' }}
                  onClick={() => onLegendProtocolClick(null)}
                >
                  Clear filter ×
                </button>
              )}
            </div>
            <small className="text-muted d-block mb-1" style={{ fontSize: '0.7rem' }}>
              Click to isolate
            </small>
            {EDGE_LEGEND.filter(({ key }) => presentEdgeLegendKeys.has(key)).map(({ label, key, color }) => (
              <button
                key={key}
                className={`legend-item-btn ${activeLegendProtocol === key ? 'active' : ''} ${activeLegendProtocol && activeLegendProtocol !== key ? 'dimmed' : ''}`}
                onClick={() => onLegendProtocolClick(activeLegendProtocol === key ? null : key)}
                title={`Show only ${label} traffic`}
              >
                <span className="legend-color" style={{ background: color }}></span>
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
