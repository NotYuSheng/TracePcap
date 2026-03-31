import { useRef, useEffect } from 'react';
import { deviceTypeIcon, deviceTypeLabel, deviceTypeColor } from '@/utils/deviceType';

export interface DeviceClassificationInfo {
  ip: string;
  deviceType: string;
  confidence: number;
  manufacturer?: string;
  ttl?: number;
}

function confidenceLevel(pct: number): string {
  if (pct >= 75) return 'Strong';
  if (pct >= 50) return 'Moderate';
  if (pct >= 25) return 'Low';
  return 'Uncertain';
}

function buildSignals(info: DeviceClassificationInfo): string[] {
  const signals: string[] = [];
  if (info.manufacturer) {
    signals.push(`MAC OUI matched: ${info.manufacturer}`);
  }
  if (info.ttl != null) {
    const os =
      info.ttl <= 64
        ? 'Linux / Android / iOS'
        : info.ttl <= 128
          ? 'Windows'
          : 'Network device (Cisco / BSD)';
    signals.push(`TTL ${info.ttl} fingerprint → ${os}`);
  }
  if (info.confidence >= 60) {
    signals.push('Application traffic profile analysed');
  }
  if (info.confidence >= 25) {
    signals.push('Network traffic patterns analysed (ports, peer count)');
  }
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
        minWidth: '280px',
        maxWidth: '360px',
        boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
        borderRadius: '8px',
        backgroundColor: '#fff',
        border: '1px solid #dee2e6',
      }}
    >
      <div
        style={{ backgroundColor: badgeBg, borderRadius: '8px 8px 0 0', padding: '10px 14px' }}
        className="d-flex align-items-center justify-content-between"
      >
        <span style={{ color: '#fff', fontWeight: 600, fontSize: '0.95rem' }}>
          {deviceTypeIcon(info.deviceType)} {deviceTypeLabel(info.deviceType)}
        </span>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: '#fff',
            fontSize: '1.1rem',
            lineHeight: 1,
            cursor: 'pointer',
            padding: '0 0 0 8px',
          }}
          aria-label="Close"
        >
          ×
        </button>
      </div>
      <div style={{ padding: '12px 14px' }}>
        <p className="mb-1 small text-muted">{info.ip}</p>
        {info.manufacturer && (
          <p className="mb-2 small">
            <strong>Vendor:</strong> {info.manufacturer}
          </p>
        )}
        <div className="mb-2 d-flex align-items-center gap-2">
          <span className="small fw-semibold">Confidence:</span>
          <div
            className="flex-grow-1"
            style={{
              background: '#e9ecef',
              borderRadius: '4px',
              height: '6px',
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                width: `${info.confidence}%`,
                height: '100%',
                backgroundColor: badgeBg,
                borderRadius: '4px',
              }}
            />
          </div>
          <span className="small text-muted text-nowrap">
            {info.confidence}% — {level}
          </span>
        </div>
        {signals.length > 0 && (
          <>
            <p className="mb-1 small fw-semibold">Signals used:</p>
            <ul className="mb-0 ps-3" style={{ fontSize: '0.8rem' }}>
              {signals.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
