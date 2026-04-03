import { useRef, useEffect } from 'react';
import { ClassificationLegend } from '@components/common/ClassificationLegend/ClassificationLegend';
import type { NodeType, NodeTypeEvidence } from '@/features/network/types';

export interface NodeTypeInfo {
  nodeType: NodeType;
  label: string;
  badgeClass: string;
  evidence: NodeTypeEvidence;
  ip: string;
}

function buildExplanation(nodeType: NodeType, ev: NodeTypeEvidence): string[] {
  const lines: string[] = [];
  switch (nodeType) {
    case 'dns-server':
    case 'web-server':
    case 'ssh-server':
    case 'ftp-server':
    case 'mail-server':
    case 'dhcp-server':
    case 'ntp-server':
    case 'database-server':
      if (ev.dominantPort) {
        lines.push(`Accepted ${ev.connectionCount} inbound connection${ev.connectionCount !== 1 ? 's' : ''} on port ${ev.dominantPort}`);
      }
      lines.push('Only receives connections on this well-known port');
      break;
    case 'router':
      lines.push(`Communicated with ${ev.distinctPeers} distinct peers`);
      lines.push('High peer count indicates a gateway or routing device');
      break;
    case 'client':
      lines.push('Initiates outbound connections');
      lines.push('No dominant inbound server port detected');
      break;
    case 'unknown':
    default:
      lines.push('Insufficient traffic to classify');
      break;
  }
  return lines;
}

interface NodeTypePopupProps {
  info: NodeTypeInfo;
  onClose: () => void;
}

export function NodeTypePopup({ info, onClose }: NodeTypePopupProps) {
  const popupRef = useRef<HTMLDivElement>(null);
  const explanation = buildExplanation(info.nodeType, info.evidence);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (popupRef.current && !popupRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [onClose]);

  // Derive a header background from the Bootstrap badge class
  const headerStyle: React.CSSProperties = (() => {
    if (info.badgeClass.includes('bg-warning')) return { backgroundColor: '#ffc107', color: '#000' };
    if (info.badgeClass.includes('bg-success')) return { backgroundColor: '#198754', color: '#fff' };
    if (info.badgeClass.includes('bg-info')) return { backgroundColor: '#0dcaf0', color: '#000' };
    if (info.badgeClass.includes('bg-danger')) return { backgroundColor: '#dc3545', color: '#fff' };
    if (info.badgeClass.includes('bg-primary')) return { backgroundColor: '#0d6efd', color: '#fff' };
    if (info.badgeClass.includes('bg-dark')) return { backgroundColor: '#212529', color: '#fff' };
    return { backgroundColor: '#6c757d', color: '#fff' };
  })();

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
          {info.label}
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
          {explanation.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
        <ClassificationLegend highlight="type" />
      </div>
    </div>
  );
}
