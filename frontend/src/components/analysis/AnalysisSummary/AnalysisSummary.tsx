import type { AnalysisSummary as AnalysisSummaryType } from '@/types';
import './AnalysisSummary.css';

interface AnalysisSummaryProps {
  summary: AnalysisSummaryType;
}

export const AnalysisSummary = ({ summary }: AnalysisSummaryProps) => {
  const formatFileSize = (bytes: number | undefined | null): string => {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDuration = (
    start: number | undefined | null,
    end: number | undefined | null
  ): string => {
    if (!start || !end) return 'N/A';
    const durationMs = end - start;
    const seconds = Math.floor(durationMs / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    // If more than 48 hours, show in days with 1 decimal place
    if (hours > 48) {
      const days = hours / 24;
      return `${days.toFixed(1)} days`;
    }

    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
  };

  const formatNumber = (num: number | undefined | null): string => {
    return num?.toLocaleString() || '0';
  };

  return (
    <div className="analysis-summary">
      <h3 className="summary-title">Analysis Summary</h3>

      <div className="summary-cards">
        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-file-earmark-binary"></i>
          </div>
          <div className="card-content">
            <div className="card-label">File Name</div>
            <div className="card-value">{summary.fileName}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-hdd"></i>
          </div>
          <div className="card-content">
            <div className="card-label">File Size</div>
            <div className="card-value">{formatFileSize(summary.fileSize)}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-stack"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Total Packets</div>
            <div className="card-value">{formatNumber(summary.totalPackets)}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-clock-history"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Duration</div>
            <div className="card-value">
              {formatDuration(summary.timeRange?.[0], summary.timeRange?.[1])}
            </div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-diagram-3"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Protocols</div>
            <div className="card-value">{summary.protocolDistribution?.length || 0}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-hdd-network"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Unique Hosts</div>
            <div className="card-value">{summary.uniqueHosts?.length || 0}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-arrow-left-right"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Conversations</div>
            <div className="card-value">{summary.topConversations?.length || 0}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-calendar-event"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Uploaded</div>
            <div className="card-value">{new Date(summary.uploadTime).toLocaleDateString()}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
