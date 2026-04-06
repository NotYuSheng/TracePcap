import { useState } from 'react';

interface StoryInfoCardProps {
  additionalContext?: string;
  onAdditionalContextChange?: (value: string) => void;
}

export const StoryInfoCard = ({
  additionalContext,
  onAdditionalContextChange,
}: StoryInfoCardProps) => {
  const [collapsed, setCollapsed] = useState(true);

  return (
    <div className="card">
      <div
        className="card-header d-flex align-items-center justify-content-between"
        style={{ cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setCollapsed(c => !c)}
      >
        <h6 className="mb-0">
          <i className="bi bi-info-circle me-2"></i>
          How Stories Are Generated &amp; Limitations
        </h6>
        <i className={`bi bi-chevron-${collapsed ? 'down' : 'up'} text-muted`}></i>
      </div>
      {!collapsed && (
        <div className="card-body">
          <p className="text-muted small mb-2">
            The following data is sent to the configured LLM to generate the narrative:
          </p>
          <ul className="small text-muted mb-3">
            <li>File metadata, traffic summary, protocol breakdown, category distribution</li>
            <li>
              <strong>Deterministic findings (full dataset)</strong> — pre-computed by 8 detectors
              covering: nDPI risk flags, beacon/C2 patterns, TLS anomalies, volume anomalies,
              fan-out/scanning, long sessions, unknown application traffic, and port-protocol
              mismatches
            </li>
            <li>
              <strong>Full-dataset aggregates</strong> — top external ASNs, protocol risk matrix,
              TLS counts, beacon candidates
            </li>
          </ul>
          <p className="text-muted small mb-2">
            <strong>Not sent to the LLM:</strong>
          </p>
          <ul className="small text-muted mb-3">
            <li>Packet payloads and HTTP bodies</li>
            <li>DNS query names and TLS SNI</li>
            <li>Raw conversation lists (replaced by structured findings)</li>
          </ul>

          {onAdditionalContextChange !== undefined && (
            <div className="mt-3 pt-3 border-top">
              <label className="form-label small fw-semibold mb-1">
                Additional context <span className="text-muted fw-normal">(optional)</span>
              </label>
              <textarea
                className="form-control form-control-sm"
                rows={3}
                placeholder={
                  'Help the LLM produce a more relevant story by providing context it cannot see, e.g.:\n' +
                  '• Known actors or devices involved\n' +
                  '• Suspected incident type (e.g. data exfiltration, C2, lateral movement)\n' +
                  '• Purpose of the capture session or environment details\n' +
                  '• Specific IPs, ports, or time ranges to focus on'
                }
                value={additionalContext}
                onChange={e => onAdditionalContextChange(e.target.value)}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};
