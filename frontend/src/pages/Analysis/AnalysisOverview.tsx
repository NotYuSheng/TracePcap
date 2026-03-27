import { useMemo } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import { AnalysisSummary } from '@components/analysis/AnalysisSummary';
import { ProtocolBreakdownChart } from '@components/analysis/ProtocolBreakdown';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

const APP_COLORS: Record<string, string> = {
  Zoom: '#2D8CFF',
  WhatsApp: '#25D366',
  Telegram: '#2AABEE',
  Signal: '#3A76F0',
  Discord: '#5865F2',
  Teams: '#6264A7',
  Skype: '#00AFF0',
  Viber: '#7360F2',
  WeChat: '#07C160',
  YouTube: '#FF0000',
  Netflix: '#E50914',
  Spotify: '#1DB954',
  TikTok: '#010101',
  Instagram: '#E1306C',
  Facebook: '#1877F2',
  Twitter: '#1DA1F2',
};

export const AnalysisOverview = () => {
  const { data } = useOutletContext<AnalysisOutletContext>();

  const detectedApps = useMemo(() => {
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
  }, [data.topConversations]);

  return (
    <div className="analysis-overview">
      <AnalysisSummary summary={data} />

      {detectedApps.length > 0 && (
        <div className="mt-4">
          <h5 className="mb-3">
            <i className="bi bi-app-indicator me-2"></i>
            Applications Detected
          </h5>
          <div className="d-flex flex-wrap gap-2">
            {detectedApps.map(app => (
              <span
                key={app.name}
                className="badge rounded-pill px-3 py-2 fs-6"
                style={{
                  backgroundColor: APP_COLORS[app.name] ?? '#6f42c1',
                  color: '#fff',
                }}
                title={`${app.packets.toLocaleString()} packets · ${(app.bytes / 1024).toFixed(1)} KB`}
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
