import { useEffect, useState } from 'react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { NetworkInsightsPanel } from '@/components/monitor/NetworkInsightsPanel/NetworkInsightsPanel';
import { insightsService } from '@/features/insights/services/insightsService';
import type { InsightOptions, NetworkInsight } from '@/features/insights/types/insights.types';

/** The AI write-up for one capture: shown when there is one, generated on request. */
export function SnapshotInsightsTab({ networkId, snapshotId }: { networkId: string; snapshotId: string }) {
  const [result, setResult] = useState<{ id: string; insight: NetworkInsight | null } | null>(null);
  useEffect(() => {
    let alive = true;
    insightsService
      .getSnapshotInsight(networkId, snapshotId)
      .then(ins => alive && setResult({ id: snapshotId, insight: ins }))
      .catch(() => alive && setResult({ id: snapshotId, insight: null }));
    return () => {
      alive = false;
    };
  }, [networkId, snapshotId]);

  const handleGenerate = async (options: InsightOptions) => {
    const ins = await insightsService.generateSnapshotInsight(networkId, snapshotId, options);
    setResult({ id: snapshotId, insight: ins });
  };

  if (result?.id !== snapshotId) {
    return (
      <div className="text-center py-4">
        <Spinner animation="border" className="text-primary" />
      </div>
    );
  }
  return <NetworkInsightsPanel insight={result.insight} llmAvailable={true} onGenerate={handleGenerate} />;
}
