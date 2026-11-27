import type { AnalysisSummary as AnalysisSummaryType } from '@/types';
import './AnalysisSummary.css';
import { formatBytes, formatDuration, formatNumber } from '@/utils/formatters';

interface AnalysisSummaryProps {
  summary: AnalysisSummaryType;
  extractedFilesCount?: number;
}

export const AnalysisSummary = ({ summary, extractedFilesCount }: AnalysisSummaryProps) => {

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
            <div className="card-value">{formatBytes(summary.fileSize)}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-stack"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Total Packets</div>
            <div className="card-value">{formatNumber(summary.totalPackets ?? 0)}</div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-clock-history"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Duration</div>
            <div className="card-value">
              {summary.timeRange?.[0] && summary.timeRange?.[1] ? formatDuration(Math.max(0, Math.round(summary.timeRange[1] - summary.timeRange[0]))) : 'N/A'}
            </div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-file-earmark-arrow-down"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Files Detected</div>
            <div className="card-value">
              {extractedFilesCount != null ? extractedFilesCount : '—'}
            </div>
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
            <div className="card-value">
              {summary.totalConversations ?? summary.topConversations?.length ?? 0}
            </div>
          </div>
        </div>

        <div className="summary-card">
          <div className="card-icon">
            <i className="bi bi-calendar-event"></i>
          </div>
          <div className="card-content">
            <div className="card-label">Uploaded</div>
            <div className="card-value">{new Date(summary.uploadTime).toLocaleDateString('en-GB')}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
