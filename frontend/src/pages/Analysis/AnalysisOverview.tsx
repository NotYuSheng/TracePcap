import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';
import { CategoryBreakdownChart } from '@components/analysis/CategoryBreakdown';
import { getAppColor, getTextColor } from '@/utils/appColors';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const AnalysisOverview = () => {
  const { data, fileId } = useOutletContext<AnalysisOutletContext>();
  const navigate = useNavigate();

  const detectedApps = data.detectedApplications ?? [];

  return (
    <div className="analysis-overview">
      <AnalysisSummary summary={data} />

      {detectedApps.length > 0 && (
        <div className="mt-4">
          <h5 className="mb-3">
            <i className="bi bi-app-indicator me-2"></i>
            Applications Detected
            {data.detectedApplicationsTruncated && (
              <span className="text-muted fs-6 fw-normal ms-2">(showing top {detectedApps.length})</span>
            )}
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {detectedApps.map(app => (
              <button
                key={app.name}
                className="badge rounded-pill px-3 py-2 fs-6 border-0"
                style={{
                  backgroundColor: getAppColor(app.name),
                  color: getTextColor(getAppColor(app.name)),
                  cursor: 'pointer',
                }}
                title={`${(app.packetCount ?? 0).toLocaleString()} packets · ${((app.bytes ?? 0) / 1024).toFixed(1)} KB — click to filter conversations`}
                onClick={() => navigate(`/analysis/${fileId}/conversations?app=${encodeURIComponent(app.name)}`)}
              >
                {app.name}
              </button>
            ))}
          </div>
        </div>
      )}

      {data.protocolDistribution && data.protocolDistribution.length > 0 && (
        <div className="mt-4">
          <ProtocolBreakdownChart protocolStats={data.protocolDistribution} />
        </div>
      )}

      {data.categoryDistribution && data.categoryDistribution.length > 0 && (
        <div className="mt-4">
          <CategoryBreakdownChart categoryStats={data.categoryDistribution} />
        </div>
      )}

      <div className="alert alert-info mt-4 mb-0 small" role="note">
        <i className="bi bi-info-circle me-2"></i>
        <strong>About application detection:</strong> Application and category labels are
        detected by <a href="https://www.ntop.org/products/deep-packet-inspection/ndpi/" target="_blank" rel="noreferrer">nDPI</a> using
        deep packet inspection heuristics. DPI is probabilistic — some flows may be misclassified,
        especially when payload patterns resemble another protocol (e.g. binary file transfers
        matching peer-to-peer signatures). Encrypted traffic (TLS/QUIC) is identified by metadata
        such as SNI, JA3 fingerprints, and port, not payload content. Treat labels as strong
        indicators, not definitive classifications. If you see an unexpected application label,
        cross-reference the destination IP/port and raw packet payload for confirmation.
      </div>
    </div>
  );
};
