import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';
import { CategoryBreakdownChart } from '@components/analysis/CategoryBreakdown';
import { getAppColor } from '@/utils/appColors';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const AnalysisOverview = () => {
  const { data } = useOutletContext<AnalysisOutletContext>();

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
              <span className="text-muted fs-6 fw-normal ms-2">
                (showing top {detectedApps.length})
              </span>
            )}
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {detectedApps.map(app => (
              <span
                key={app.name}
                className="badge rounded-pill px-3 py-2 fs-6"
                style={{
                  backgroundColor: getAppColor(app.name),
                  color: '#fff',
                }}
                title={`${(app.packetCount ?? 0).toLocaleString()} packets · ${((app.bytes ?? 0) / 1024).toFixed(1)} KB`}
              >
                {app.name}
              </span>
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
    </div>
  );
};
