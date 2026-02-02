import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

export const AnalysisOverview = () => {
  const { data } = useOutletContext<AnalysisOutletContext>();

  return (
    <div className="analysis-overview">
      <AnalysisSummary summary={data} />

      {data.protocolDistribution && data.protocolDistribution.length > 0 && (
        <div className="mt-4">
          <ProtocolBreakdownChart protocolStats={data.protocolDistribution} />
        </div>
      )}
    </div>
  );
};
