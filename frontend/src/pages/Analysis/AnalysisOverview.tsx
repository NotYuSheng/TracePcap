import { useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';
import { getAppColor } from '@/utils/appColors';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const AnalysisOverview = () => {
  const { data } = useOutletContext<AnalysisOutletContext>();

  const detectedApps = useMemo(() => {
    if (data.detectedApplications && data.detectedApplications.length > 0) {
      return data.detectedApplications.map(name => ({ name }));
    }
    // Fallback: derive from topConversations (may be incomplete)
    const appMap = new Map<string, { packets: number; bytes: number }>();
    for (const conv of data.topConversations || []) {
      if (!conv.appName) continue;
      const existing = appMap.get(conv.appName) || { packets: 0, bytes: 0 };
      appMap.set(conv.appName, {
        packets: existing.packets + conv.packetCount,
        bytes: existing.bytes + conv.totalBytes,
      });
    }
    return Array.from(appMap.entries())
      .map(([name, stats]) => ({ name, ...stats }))
      .sort((a, b) => b.bytes - a.bytes);
  }, [data.detectedApplications, data.topConversations]);

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
              <span
                key={app.name}
                className="badge rounded-pill px-3 py-2 fs-6"
                style={{
                  backgroundColor: getAppColor(app.name),
                  color: '#fff',
                }}
                title={'packets' in app ? `${app.packets.toLocaleString()} packets · ${(app.bytes / 1024).toFixed(1)} KB` : app.name}
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
    </div>
  );
};
