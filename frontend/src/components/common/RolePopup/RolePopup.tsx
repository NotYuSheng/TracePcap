import { useRef, useEffect } from 'react';
import { ClassificationLegend } from '@components/common/ClassificationLegend/ClassificationLegend';

export interface RoleInfo {
  ip: string;
  role: 'client' | 'server' | 'both' | 'unknown';
  initiated: number;
  received: number;
}

function roleColor(role: string): { backgroundColor: string; color: string } {
  switch (role) {
    case 'client': return { backgroundColor: '#0d6efd', color: '#fff' };
    case 'server': return { backgroundColor: '#198754', color: '#fff' };
    case 'both':   return { backgroundColor: '#6c757d', color: '#fff' };
    default:       return { backgroundColor: '#dee2e6', color: '#000' };
  }
}

function roleLabel(role: string): string {
  switch (role) {
    case 'client': return 'Client';
    case 'server': return 'Server';
    case 'both':   return 'Both';
    default:       return 'Unknown';
  }
}

function buildSignals(info: RoleInfo): string[] {
  const lines: string[] = [];
  const total = info.initiated + info.received;
  if (info.initiated > 0)
    lines.push(`Initiated ${info.initiated} conversation${info.initiated !== 1 ? 's' : ''}`);
  if (info.received > 0)
    lines.push(`Received ${info.received} inbound conversation${info.received !== 1 ? 's' : ''}`);
  if (total === 0)
    lines.push('No conversations observed');
  switch (info.role) {
    case 'client':
      lines.push('Exclusively opens connections to other hosts');
      break;
    case 'server':
      lines.push('Exclusively accepts inbound connections');
      break;
    case 'both':
      lines.push('Acts as both initiator and responder');
      break;
  }
  return lines;
}

interface RolePopupProps {
  info: RoleInfo;
  onClose: () => void;
}

export function RolePopup({ info, onClose }: RolePopupProps) {
  const popupRef = useRef<HTMLDivElement>(null);
  const signals = buildSignals(info);
  const headerStyle = roleColor(info.role);

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
        style={{ ...headerStyle, borderRadius: '8px 8px 0 0', padding: '10px 14px' }}
        className="d-flex align-items-center justify-content-between"
      >
        <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>
          {roleLabel(info.role)}
        </span>
        <button
          onClick={onClose}
          style={{
            background: 'none',
            border: 'none',
            color: 'inherit',
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
        <p className="mb-2 small text-muted">{info.ip}</p>
        <p className="mb-1 small fw-semibold">Classification signals:</p>
        <ul className="mb-2 ps-3" style={{ fontSize: '0.8rem' }}>
          {signals.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ul>
        <ClassificationLegend highlight="role" />
      </div>
    </div>
  );
}
