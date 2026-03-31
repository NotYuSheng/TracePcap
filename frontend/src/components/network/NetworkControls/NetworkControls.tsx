import { useState } from 'react';
import type { NetworkStats } from '@/features/network/types';
import { PROTOCOL_COLORS, NODE_TYPE_COLORS } from '@/features/network/constants';
import { DEVICE_TYPES, deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';
import './NetworkControls.css';

interface NetworkControlsProps {
  stats: NetworkStats;
  layoutType: 'forceDirected2d' | 'hierarchicalTd';
  onLayoutChange: (layout: 'forceDirected2d' | 'hierarchicalTd') => void;
  activeLegendProtocols: string[];
  onLegendProtocolClick: (key: string) => void;
  onLegendProtocolClear: () => void;
  activeLegendNodeTypes: string[];
  onLegendNodeTypeClick: (key: string) => void;
  onLegendNodeTypeClear: () => void;
  presentNodeTypes: Set<string>;
  presentEdgeLegendKeys: Set<string>;
  activeLegendDeviceTypes: string[];
  onLegendDeviceTypeClick: (key: string) => void;
  onLegendDeviceTypeClear: () => void;
  presentDeviceTypes: Set<string>;
}

const EDGE_LEGEND = [
  { label: 'HTTP', key: 'HTTP', color: PROTOCOL_COLORS['HTTP'] },
  { label: 'HTTPS/TLS', key: 'HTTPS', color: PROTOCOL_COLORS['HTTPS'] },
  { label: 'DNS', key: 'DNS', color: PROTOCOL_COLORS['DNS'] },
  { label: 'TCP', key: 'TCP', color: PROTOCOL_COLORS['TCP'] },
  { label: 'UDP', key: 'UDP', color: PROTOCOL_COLORS['UDP'] },
];

const NODE_LEGEND = [
  { label: 'DNS Server', key: 'dns-server', color: NODE_TYPE_COLORS['dns-server'] },
  { label: 'Web Server', key: 'web-server', color: NODE_TYPE_COLORS['web-server'] },
  { label: 'SSH Server', key: 'ssh-server', color: NODE_TYPE_COLORS['ssh-server'] },
  { label: 'FTP Server', key: 'ftp-server', color: NODE_TYPE_COLORS['ftp-server'] },
  { label: 'Mail Server', key: 'mail-server', color: NODE_TYPE_COLORS['mail-server'] },
  { label: 'DHCP Server', key: 'dhcp-server', color: NODE_TYPE_COLORS['dhcp-server'] },
  { label: 'NTP Server', key: 'ntp-server', color: NODE_TYPE_COLORS['ntp-server'] },
  { label: 'Database Server', key: 'database-server', color: NODE_TYPE_COLORS['database-server'] },
  { label: 'Router / Gateway', key: 'router', color: NODE_TYPE_COLORS['router'] },
  { label: 'Client', key: 'client', color: NODE_TYPE_COLORS['client'] },
  { label: 'Anomaly', key: 'anomaly', color: NODE_TYPE_COLORS['anomaly'] },
  { label: 'Unknown', key: 'unknown', color: NODE_TYPE_COLORS['unknown'] },
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
  activeLegendProtocols,
  onLegendProtocolClick,
  onLegendProtocolClear,
  activeLegendNodeTypes,
  onLegendNodeTypeClick,
  onLegendNodeTypeClear,
  presentNodeTypes,
  presentEdgeLegendKeys,
  activeLegendDeviceTypes,
  onLegendDeviceTypeClick,
  onLegendDeviceTypeClear,
  presentDeviceTypes,
}: NetworkControlsProps) {
  const [showColorInfo, setShowColorInfo] = useState(false);

  return (
    <>
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
        <div className="card-header d-flex justify-content-between align-items-center">
          <strong>Legend</strong>
          <button
            className="btn btn-link btn-sm p-0 text-muted"
            onClick={() => setShowColorInfo(true)}
            title="How are node colours determined?"
          >
            <i className="bi bi-info-circle"></i>
          </button>
        </div>
        <div className="card-body p-2">
          <div className="legend-section mb-2">
            <div className="legend-title d-flex justify-content-between align-items-center">
              <span>Node Types</span>
              {activeLegendNodeTypes.length > 0 && (
                <button
                  className="btn btn-link btn-sm p-0 text-muted legend-small-text"
                  onClick={onLegendNodeTypeClear}
                >
                  Clear ×
                </button>
              )}
            </div>
            <small className="text-muted d-block mb-1 legend-small-text">
              Click to filter (multi-select)
            </small>
            {NODE_LEGEND.filter(({ key }) => presentNodeTypes.has(key)).map(
              ({ label, key, color }) => (
                <button
                  key={key}
                  className={`legend-item-btn ${activeLegendNodeTypes.includes(key) ? 'active' : ''} ${activeLegendNodeTypes.length > 0 && !activeLegendNodeTypes.includes(key) ? 'dimmed' : ''}`}
                  onClick={() => onLegendNodeTypeClick(key)}
                  title={`${activeLegendNodeTypes.includes(key) ? 'Deselect' : 'Select'} ${label}`}
                >
                  <span className="legend-color" style={{ background: color }}></span>
                  {label}
                </button>
              )
            )}
          </div>
          {presentDeviceTypes.size > 0 && (
            <div className="legend-section mb-2">
              <div className="legend-title d-flex justify-content-between align-items-center">
                <span>Device Types</span>
                {activeLegendDeviceTypes.length > 0 && (
                  <button
                    className="btn btn-link btn-sm p-0 text-muted legend-small-text"
                    onClick={onLegendDeviceTypeClear}
                  >
                    Clear ×
                  </button>
                )}
              </div>
              <small className="text-muted d-block mb-1 legend-small-text">
                Click to filter (multi-select)
              </small>
              {DEVICE_TYPES.filter(dt => presentDeviceTypes.has(dt)).map(dt => (
                <button
                  key={dt}
                  className={`legend-item-btn ${activeLegendDeviceTypes.includes(dt) ? 'active' : ''} ${activeLegendDeviceTypes.length > 0 && !activeLegendDeviceTypes.includes(dt) ? 'dimmed' : ''}`}
                  onClick={() => onLegendDeviceTypeClick(dt)}
                  title={`${activeLegendDeviceTypes.includes(dt) ? 'Deselect' : 'Select'} ${deviceTypeLabel(dt)}`}
                >
                  <span className="legend-color" style={{ background: deviceTypeColor(dt) }}></span>
                  {deviceTypeLabel(dt)}
                </button>
              ))}
            </div>
          )}

          <div className="legend-section">
            <div className="legend-title d-flex justify-content-between align-items-center">
              <span>Edge Protocols</span>
              {activeLegendProtocols.length > 0 && (
                <button
                  className="btn btn-link btn-sm p-0 text-muted legend-small-text"
                  onClick={onLegendProtocolClear}
                >
                  Clear ×
                </button>
              )}
            </div>
            <small className="text-muted d-block mb-1 legend-small-text">
              Click to filter (multi-select)
            </small>
            {EDGE_LEGEND.filter(({ key }) => presentEdgeLegendKeys.has(key)).map(
              ({ label, key, color }) => (
                <button
                  key={key}
                  className={`legend-item-btn ${activeLegendProtocols.includes(key) ? 'active' : ''} ${activeLegendProtocols.length > 0 && !activeLegendProtocols.includes(key) ? 'dimmed' : ''}`}
                  onClick={() => onLegendProtocolClick(key)}
                  title={`${activeLegendProtocols.includes(key) ? 'Deselect' : 'Select'} ${label}`}
                >
                  <span className="legend-color" style={{ background: color }}></span>
                  {label}
                </button>
              )
            )}
          </div>
        </div>
      </div>
    </div>

    {showColorInfo && (
      <div
        className="modal fade show d-block"
        style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}
        onClick={e => { if (e.target === e.currentTarget) setShowColorInfo(false); }}
      >
        <div className="modal-dialog modal-dialog-scrollable">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">
                <i className="bi bi-palette me-2"></i>
                Node Colour Priority
              </h5>
              <button type="button" className="btn-close" onClick={() => setShowColorInfo(false)} />
            </div>
            <div className="modal-body">
              <p className="text-muted small mb-3">
                Each node's colour is determined by the first rule that matches, in order of priority:
              </p>
              <ol className="ps-3" style={{ lineHeight: '2' }}>
                <li>
                  <span
                    className="badge me-2"
                    style={{ backgroundColor: NODE_TYPE_COLORS['anomaly'], color: '#fff' }}
                  >
                    Anomaly
                  </span>
                  <strong>Anomaly detected</strong> — always shown in red regardless of type.
                </li>
                <li>
                  <span className="badge bg-warning text-dark me-2">Specific server role</span>
                  <strong>Port-based server classification</strong> — DNS, web, SSH, FTP, mail,
                  DHCP, NTP, database, and router nodes keep their dedicated colours because their
                  role is well-defined by the ports they serve.
                </li>
                <li>
                  <span className="badge me-2" style={{ backgroundColor: '#8b5cf6', color: '#fff' }}>Device type</span>
                  <strong>Device classification</strong> — for generic nodes (client / unknown),
                  the device type detected by the backend classifier (Mobile, Laptop/Desktop, IoT,
                  etc.) takes over. These colours appear in the <em>Device Types</em> section of
                  the legend.
                </li>
                <li>
                  <span
                    className="badge me-2"
                    style={{ backgroundColor: NODE_TYPE_COLORS['client'], color: '#fff' }}
                  >
                    Client
                  </span>
                  <strong>Generic node type</strong> — if no device type is resolved, the
                  port-based classification colour is used (e.g. blue for client, grey for
                  unknown).
                </li>
                <li>
                  <span className="badge bg-secondary me-2">Role fallback</span>
                  <strong>Traffic role</strong> — last resort: green for server, purple for
                  client-and-server combined, grey for everything else.
                </li>
              </ol>
            </div>
          </div>
        </div>
      </div>
    )}
    </>
  );
}
