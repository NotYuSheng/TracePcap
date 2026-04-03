import { useRef, useEffect } from 'react';
import { deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';
import { portToServiceLabel } from '@/utils/portUtils';

export interface DeviceClassificationInfo {
  ip: string;
  deviceType: string;
  confidence: number;
  manufacturer?: string;
  ttl?: number;
  role?: 'client' | 'server';
  conversationPort?: number;
}

function confidenceLevel(pct: number): string {
  if (pct >= 75) return 'Strong';
  if (pct >= 50) return 'Moderate';
  if (pct >= 25) return 'Low';
  return 'Uncertain';
}

function buildSignals(info: DeviceClassificationInfo): string[] {
  const signals: string[] = [];
  if (info.manufacturer) signals.push(`MAC OUI matched: ${info.manufacturer}`);
  if (info.ttl != null) {
    const os =
      info.ttl <= 64 ? 'Linux / Android / iOS' :
      info.ttl <= 128 ? 'Windows' :
      'Network device (Cisco / BSD)';
    signals.push(`TTL ${info.ttl} → ${os}`);
  }
  if (info.confidence >= 60) signals.push('Application traffic profile analysed');
  if (info.confidence >= 25) signals.push('Network traffic patterns analysed');
  return signals;
}

interface DeviceClassificationPopupProps {
  info: DeviceClassificationInfo;
  onClose: () => void;
}

export function DeviceClassificationPopup({ info, onClose }: DeviceClassificationPopupProps) {
  const popupRef = useRef<HTMLDivElement>(null);
  const signals = buildSignals(info);
  const level = confidenceLevel(info.confidence);
  const badgeBg = deviceTypeColor(info.deviceType);

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
        style={{ backgroundColor: badgeBg, borderRadius: '8px 8px 0 0', padding: '10px 14px' }}
        className="d-flex align-items-center justify-content-between"
      >
        <span style={{ color: '#fff', fontWeight: 600, fontSize: '0.95rem' }}>Classification</span>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', color: '#fff', fontSize: '1.1rem', lineHeight: 1, cursor: 'pointer', padding: '0 0 0 8px' }}
          aria-label="Close"
        >×</button>
      </div>

      <div style={{ padding: '12px 14px' }}>
        <p className="mb-2 small text-muted">{info.ip}</p>

        {/* Type row */}
        {(() => {
          let typeLabel: string | null = null;
          let typeNote: string | null = null;
          if (info.role === 'client') {
            typeLabel = 'Client';
            typeNote = 'Initiated this conversation';
          } else if (info.role === 'server' && info.conversationPort != null) {
            typeLabel = portToServiceLabel(info.conversationPort) ?? 'Server';
            typeNote = `Based on destination port ${info.conversationPort} in this conversation`;
          }
          if (!typeLabel) return null;
          return (
            <div className="d-flex align-items-start gap-2 mb-2">
              <span className="text-muted small" style={{ minWidth: '52px', paddingTop: '2px' }}>Type</span>
              <div>
                <span className="badge bg-secondary">{typeLabel}</span>
                {typeNote && <div className="mt-1" style={{ fontSize: '0.75rem', color: '#6c757d' }}>{typeNote}</div>}
              </div>
            </div>
          );
        })()}

        {/* Device row */}
        <div className="d-flex align-items-start gap-2 mb-2">
          <span className="text-muted small" style={{ minWidth: '52px', paddingTop: '2px' }}>Device</span>
          <div style={{ flex: 1 }}>
            <span className="badge" style={{ backgroundColor: badgeBg, color: '#fff' }}>
              {deviceTypeLabel(info.deviceType)}
            </span>
            {signals.length > 0 && (
              <ul className="mb-1 ps-3 mt-1" style={{ fontSize: '0.75rem', color: '#6c757d' }}>
                {signals.map((s, i) => <li key={i}>{s}</li>)}
              </ul>
            )}
            <div className="d-flex align-items-center gap-2 mt-1">
              <div style={{ flex: 1, background: '#e9ecef', borderRadius: '4px', height: '4px', overflow: 'hidden' }}>
                <div style={{ width: `${info.confidence}%`, height: '100%', backgroundColor: badgeBg, borderRadius: '4px' }} />
              </div>
              <span style={{ fontSize: '0.72rem', color: '#6c757d', whiteSpace: 'nowrap' }}>
                {info.confidence}% — {level}
              </span>
            </div>
          </div>
        </div>

        {/* Role row */}
        {info.role && (
          <div className="d-flex align-items-start gap-2 mb-0">
            <span className="text-muted small" style={{ minWidth: '52px', paddingTop: '2px' }}>Role</span>
            <div>
              <span className={`badge ${info.role === 'client' ? 'bg-primary' : 'bg-success'}`}>
                {info.role.charAt(0).toUpperCase() + info.role.slice(1)}
              </span>
              <div className="mt-1" style={{ fontSize: '0.75rem', color: '#6c757d' }}>
                {info.role === 'client' ? 'Initiated this conversation' : 'Received this conversation'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
