import { useMemo } from 'react';
import type { NetworkStats } from '@/features/network/types';
import './NetworkControls.css';

interface NetworkControlsProps {
  stats: NetworkStats;
  selectedProtocols: string[];
  onProtocolFilterChange: (protocols: string[]) => void;
  layoutType: 'forceDirected2d' | 'hierarchicalTd';
  onLayoutChange: (layout: 'forceDirected2d' | 'hierarchicalTd') => void;
}

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
  selectedProtocols,
  onProtocolFilterChange,
  layoutType,
  onLayoutChange,
}: NetworkControlsProps) {
  // Get available protocols from stats
  const availableProtocols = useMemo(() => {
    return Object.keys(stats.protocolBreakdown).sort();
  }, [stats.protocolBreakdown]);

  const handleProtocolToggle = (protocol: string) => {
    if (selectedProtocols.includes(protocol)) {
      onProtocolFilterChange(selectedProtocols.filter(p => p !== protocol));
    } else {
      onProtocolFilterChange([...selectedProtocols, protocol]);
    }
  };

  const handleSelectAll = () => {
    onProtocolFilterChange(availableProtocols);
  };

  const handleDeselectAll = () => {
    onProtocolFilterChange([]);
  };

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

      {/* Protocol Filter */}
      <div className="mb-3">
        <label className="form-label">
          <strong>Filter by Protocol</strong>
        </label>
        <div className="mb-2">
          <button className="btn btn-sm btn-outline-secondary me-2" onClick={handleSelectAll}>
            Select All
          </button>
          <button className="btn btn-sm btn-outline-secondary" onClick={handleDeselectAll}>
            Deselect All
          </button>
        </div>
        <div className="protocol-filter-list">
          {availableProtocols.map(protocol => (
            <div key={protocol} className="form-check">
              <input
                className="form-check-input"
                type="checkbox"
                id={`protocol-${protocol}`}
                checked={selectedProtocols.includes(protocol)}
                onChange={() => handleProtocolToggle(protocol)}
              />
              <label className="form-check-label" htmlFor={`protocol-${protocol}`}>
                {protocol}
                <span className="text-muted ms-2">
                  ({formatNumber(stats.protocolBreakdown[protocol])})
                </span>
              </label>
            </div>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="card">
        <div className="card-header">
          <strong>Legend</strong>
        </div>
        <div className="card-body p-2">
          <div className="legend-section mb-2">
            <div className="legend-title">Node Roles</div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#3498db' }}></span>
              Client
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#2ecc71' }}></span>
              Server
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#9b59b6' }}></span>
              Both
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#e74c3c' }}></span>
              Anomaly
            </div>
          </div>
          <div className="legend-section">
            <div className="legend-title">Edge Protocols</div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#2ecc71' }}></span>
              HTTP
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#3498db' }}></span>
              HTTPS/TLS
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#f39c12' }}></span>
              DNS
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#7f8c8d' }}></span>
              TCP
            </div>
            <div className="legend-item">
              <span className="legend-color" style={{ background: '#f1c40f' }}></span>
              UDP
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
