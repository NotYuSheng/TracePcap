import { useRef, useEffect } from 'react';
import type { NodeType, NodeTypeEvidence } from '@/features/network/types';
import type { DeviceType } from '@/types';
import { deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';

export interface NodeClassificationInfo {
  ip: string;
  // Type
  nodeType: NodeType;
  typeLabel: string;
  typeBadgeClass: string;
  typeEvidence: NodeTypeEvidence;
  // Role
  role: 'client' | 'server' | 'both' | 'unknown';
  initiated: number;
  received: number;
  // Device (optional)
  deviceType?: DeviceType;
  deviceConfidence?: number;
  manufacturer?: string;
  ttl?: number;
}

function confidenceLevel(pct: number): string {
  if (pct >= 75) return 'Strong';
  if (pct >= 50) return 'Moderate';
  if (pct >= 25) return 'Low';
  return 'Uncertain';
}

function typeEvidence(nodeType: NodeType, ev: NodeTypeEvidence): string {
  switch (nodeType) {
    case 'router':
      return `${ev.distinctPeers} distinct peers`;
    case 'client':
    case 'unknown':
      return 'No dominant inbound port';
    default:
      return ev.dominantPort
        ? `${ev.connectionCount} connection${ev.connectionCount !== 1 ? 's' : ''} on port ${ev.dominantPort}`
        : '';
  }
}

function buildDeviceSignals(info: NodeClassificationInfo): string[] {
  const signals: string[] = [];
  if (info.manufacturer) signals.push(`MAC OUI matched: ${info.manufacturer}`);
  if (info.ttl != null) {
    const os = info.ttl <= 64 ? 'Linux / Android / iOS' : info.ttl <= 128 ? 'Windows' : 'Network device (Cisco / BSD)';
    signals.push(`TTL ${info.ttl} → ${os}`);
  }
  if ((info.deviceConfidence ?? 0) >= 60) signals.push('Application traffic profile analysed');
  if ((info.deviceConfidence ?? 0) >= 25) signals.push('Network traffic patterns analysed');
  return signals;
}

function headerStyleFromBadgeClass(badgeClass: string): React.CSSProperties {
  if (badgeClass.includes('bg-warning')) return { backgroundColor: '#ffc107', color: '#000' };
  if (badgeClass.includes('bg-success')) return { backgroundColor: '#198754', color: '#fff' };
  if (badgeClass.includes('bg-info'))    return { backgroundColor: '#0dcaf0', color: '#000' };
  if (badgeClass.includes('bg-danger'))  return { backgroundColor: '#dc3545', color: '#fff' };
  if (badgeClass.includes('bg-primary')) return { backgroundColor: '#0d6efd', color: '#fff' };
  if (badgeClass.includes('bg-dark'))    return { backgroundColor: '#212529', color: '#fff' };
  return { backgroundColor: '#6c757d', color: '#fff' };
}

interface Props {
  info: NodeClassificationInfo;
  onClose: () => void;
}

export function NodeClassificationPopup({ info, onClose }: Props) {
  const popupRef = useRef<HTMLDivElement>(null);
  const headerStyle = headerStyleFromBadgeClass(info.typeBadgeClass);
  const evText = typeEvidence(info.nodeType, info.typeEvidence);
  const deviceBg = info.deviceType ? deviceTypeColor(info.deviceType) : undefined;
  const confidence = info.deviceConfidence ?? 0;
  const deviceSignals = buildDeviceSignals(info);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (popupRef.current && !popupRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [onClose]);

  return (
    <div
      ref={popupRef}
      style={{
        position: 'fixed',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        zIndex: 9999,
        minWidth: '300px',
        maxWidth: '380px',
        boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
        borderRadius: '8px',
        backgroundColor: '#fff',
        border: '1px solid #dee2e6',
      }}
    >
      {/* Header */}
      <div
        style={{ ...headerStyle, borderRadius: '8px 8px 0 0', padding: '10px 14px' }}
        className="d-flex align-items-center justify-content-between"
      >
        <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>Classification</span>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: 'inherit', fontSize: '1.1rem', lineHeight: 1, cursor: 'pointer', padding: '0 0 0 8px' }}
          aria-label="Close"
        >×</button>
      </div>

      <div style={{ padding: '12px 14px' }}>
        <p className="mb-2 small text-muted">{info.ip}</p>

        {/* Type row */}
        <div className="d-flex align-items-start gap-2 mb-2">
          <span className="text-muted small" style={{ minWidth: '52px', paddingTop: '2px' }}>Type</span>
          <div>
            <span className={`badge ${info.typeBadgeClass}`}>{info.typeLabel}</span>
            {evText && <div className="text-muted mt-1" style={{ fontSize: '0.75rem' }}>{evText}</div>}
          </div>
        </div>

        {/* Device row */}
        {info.deviceType && (
          <div className="d-flex align-items-start gap-2 mb-2">
            <span className="text-muted small" style={{ minWidth: '52px', paddingTop: '2px' }}>Device</span>
            <div style={{ flex: 1 }}>
              <span className="badge" style={{ backgroundColor: deviceBg, color: '#fff' }}>
                {deviceTypeLabel(info.deviceType)}
              </span>
              {deviceSignals.length > 0 && (
                <ul className="mb-1 ps-3 mt-1" style={{ fontSize: '0.75rem', color: '#6c757d' }}>
                  {deviceSignals.map((s, i) => <li key={i}>{s}</li>)}
                </ul>
              )}
              <div className="d-flex align-items-center gap-2 mt-1">
                <div style={{ flex: 1, background: '#e9ecef', borderRadius: '4px', height: '4px', overflow: 'hidden' }}>
                  <div style={{ width: `${confidence}%`, height: '100%', backgroundColor: deviceBg, borderRadius: '4px' }} />
                </div>
                <span style={{ fontSize: '0.72rem', color: '#6c757d', whiteSpace: 'nowrap' }}>
                  {confidence}% — {confidenceLevel(confidence)}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Role row */}
        <div className="d-flex align-items-start gap-2 mb-2">
          <span className="text-muted small" style={{ minWidth: '52px', paddingTop: '2px' }}>Role</span>
          <div>
            <span className="badge bg-secondary">
              {info.role.charAt(0).toUpperCase() + info.role.slice(1)}
            </span>
            <div className="text-muted mt-1" style={{ fontSize: '0.75rem' }}>
              {info.initiated} initiated · {info.received} received
            </div>
          </div>
        </div>

        {/* Legend */}
        <table className="table table-sm table-bordered mb-0 mt-2" style={{ fontSize: '0.72rem' }}>
          <thead className="table-light">
            <tr><th></th><th>Source</th><th>Signal used</th></tr>
          </thead>
          <tbody>
            <tr><td>Type</td><td>Network topology</td><td>Ports listened on, peer count</td></tr>
            <tr><td>Device</td><td>Hardware fingerprinting</td><td>MAC OUI, TTL, app profile</td></tr>
            <tr><td>Role</td><td>TCP session direction</td><td>Who initiates</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
