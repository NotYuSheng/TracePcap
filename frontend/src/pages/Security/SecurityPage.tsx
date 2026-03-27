import { useState, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData, Conversation } from '@/types';
import { securityService } from '@/features/security/services/securityService';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

/**
 * Risk names considered critical (red badge).
 * All others flagged by nDPI are shown as warning (amber).
 */
const CRITICAL_RISKS = new Set([
  'clear_text_credentials',
  'suspicious_entropy',
  'suspicious_dns_traffic',
  'binary_application_transfer',
  'possible_exploit_detected',
  'xss_attack',
  'sql_injection',
  'rce_injection',
]);

function riskBadgeClass(risk: string): string {
  return CRITICAL_RISKS.has(risk) ? 'badge bg-danger me-1' : 'badge bg-warning text-dark me-1';
}

function formatRiskLabel(risk: string): string {
  return risk.replace(/_/g, ' ');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const SecurityPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const [alerts, setAlerts] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!fileId) return;
    const fetch = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await securityService.getSecurityAlerts(fileId);
        setAlerts(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load security alerts');
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, [fileId]);

  if (loading) {
    return <LoadingSpinner size="large" message="Scanning for security alerts..." />;
  }

  if (error) {
    return <ErrorMessage title="Failed to Load Security Alerts" message={error} />;
  }

  if (alerts.length === 0) {
    return (
      <div className="security-page text-center py-5">
        <i className="bi bi-shield-check display-3 text-success mb-3 d-block"></i>
        <h5>No security issues detected</h5>
        <p className="text-muted">nDPI found no risk flags in any conversation for this PCAP.</p>
      </div>
    );
  }

  return (
    <div className="security-page">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h4>
          <i className="bi bi-shield-exclamation text-danger me-2"></i>
          Security Alerts ({alerts.length})
        </h4>
      </div>

      <div className="table-responsive">
        <table className="table table-hover align-middle">
          <thead className="table-light">
            <tr>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Risk Flags</th>
              <th>Packets</th>
              <th>Bytes</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map(conv => (
              <tr key={conv.id}>
                <td className="font-monospace small">
                  {conv.endpoints[0].ip}:{conv.endpoints[0].port}
                </td>
                <td className="font-monospace small">
                  {conv.endpoints[1].ip}:{conv.endpoints[1].port}
                </td>
                <td>
                  <span className="badge bg-secondary">{conv.protocol.name}</span>
                  {conv.appName && <span className="badge bg-info ms-1">{conv.appName}</span>}
                </td>
                <td>
                  {conv.flowRisks.map(risk => (
                    <span key={risk} className={riskBadgeClass(risk)} title={risk}>
                      {formatRiskLabel(risk)}
                    </span>
                  ))}
                </td>
                <td>{conv.packetCount.toLocaleString()}</td>
                <td>{formatBytes(conv.totalBytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
