import { buildDeviceSignals, confidenceLevel, type DeviceSignalInfo } from '@/utils/deviceType';
import type { HostClassification } from '../types';

interface HostClassificationSectionProps {
  hostClass: HostClassification;
}

/** Device classification signals (manufacturer/type/TTL/confidence) for an IP. */
export function HostClassificationSection({ hostClass }: HostClassificationSectionProps) {
  const signalInfo: DeviceSignalInfo = {
    manufacturer: hostClass.manufacturer ?? undefined,
    ttl: hostClass.ttl ?? undefined,
    confidence: hostClass.confidence ?? 0,
    deviceType: hostClass.deviceType ?? undefined,
    apps: [],
  };
  const { fired, missing } = buildDeviceSignals(signalInfo);

  return (
    <div className="mb-4">
      <h6 className="border-bottom pb-1 mb-2">Device Classification</h6>
      <div className="d-flex gap-4 flex-wrap mb-2">
        {hostClass.manufacturer && (
          <div>
            <small className="text-muted d-block">Manufacturer</small>
            <strong>{hostClass.manufacturer}</strong>
          </div>
        )}
        {hostClass.deviceType && (
          <div>
            <small className="text-muted d-block">Device Type</small>
            <strong>{hostClass.deviceType}</strong>
          </div>
        )}
        {hostClass.ttl != null && (
          <div>
            <small className="text-muted d-block">TTL</small>
            <strong>{hostClass.ttl}</strong>
          </div>
        )}
        {hostClass.confidence != null && (
          <div>
            <small className="text-muted d-block">Confidence</small>
            <strong>{hostClass.confidence}%{hostClass.confidence != null && <span className="text-muted fw-normal"> — {confidenceLevel(hostClass.confidence)}</span>}</strong>
          </div>
        )}
      </div>
      {fired.length > 0 && (
        <div className="border rounded p-2 mb-2" style={{ background: 'var(--tp-bg-subtle)', fontSize: '0.78rem' }}>
          <small className="text-muted fw-semibold d-block mb-1">
            <i className="bi bi-bar-chart-steps me-1" />How this is derived
          </small>
          <ul className="mb-0 ps-3">
            {fired.map((s, i) => <li key={i} className="text-muted">{s}</li>)}
          </ul>
        </div>
      )}
      {missing.length > 0 && (
        <div className="border rounded p-2" style={{ background: 'var(--bs-warning-bg-subtle, #fff3cd)', borderColor: 'var(--bs-warning-border-subtle, #ffc107)', fontSize: '0.78rem' }}>
          <small className="fw-semibold d-block mb-1" style={{ color: 'var(--bs-warning-text-emphasis, #664d03)' }}>
            <i className="bi bi-lightbulb me-1" />What would improve confidence
          </small>
          <ul className="mb-0 ps-3" style={{ color: 'var(--bs-warning-text-emphasis, #664d03)' }}>
            {missing.map((s, i) => <li key={i}>{s}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
