import { useEffect, useState } from 'react';
import { Spinner } from '@components/common/Spinner/Spinner';
import { NetworkInsightsPanel } from '@/components/monitor/NetworkInsightsPanel/NetworkInsightsPanel';
import { insightsService } from '@/features/insights/services/insightsService';
import { aiJobsService } from '@/features/aiJobs/aiJobsService';
import { useAiJob } from '@/features/aiJobs/useAiJob';
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

  // Generated in the background (one job at a time for the model): the tab follows the job.
  const job = useAiJob<NetworkInsight>('SNAPSHOT_INSIGHTS', networkId, {
    onDone: ins => { if (ins) setResult({ id: snapshotId, insight: ins }); },
  }, snapshotId);
  const handleGenerate = async (options: InsightOptions) => {
    await job.start(() => aiJobsService.startSnapshotInsights(networkId, snapshotId, options));
  };

  if (result?.id !== snapshotId) {
    return (
      <div className="text-center py-4">
        <Spinner animation="border" className="text-primary" />
      </div>
    );
  }
  return (
    <NetworkInsightsPanel
      insight={result.insight}
      llmAvailable={true}
      onGenerate={handleGenerate}
      job={job.job}
      onCancelJob={job.cancel}
    />
  );
}
