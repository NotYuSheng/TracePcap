import { useState, useEffect } from 'react';
import { useParams, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAnalysisData } from '@features/analysis/hooks/useAnalysisData';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { AnalysisLoadingView } from './AnalysisLoadingView';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { captureNetworkDiagrams } from '@/features/report/captureNetworkDiagrams';

export const AnalysisPage = () => {
  const { fileId } = useParams<{ fileId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { data, loading, error, refetch } = useAnalysisData(fileId!);
  const [activeTab, setActiveTab] = useState('overview');
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [reportStep, setReportStep] = useState<string | null>(null);

  useEffect(() => {
    const path = location.pathname;
    if (path.includes('/conversations')) setActiveTab('conversations');
    else if (path.includes('/story')) setActiveTab('story');
    else if (path.includes('/filter-generator')) setActiveTab('filter-generator');
    else if (path.includes('/network-diagram')) setActiveTab('network-diagram');
    else if (path.includes('/extracted-files')) setActiveTab('extracted-files');
    else setActiveTab('overview');
  }, [location.pathname]);

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    navigate(tab === 'overview' ? `/analysis/${fileId}` : `/analysis/${fileId}/${tab}`);
  };

  const handleDownloadReport = async () => {
    if (!fileId) return;
    setReportLoading(true);
    setReportError(null);
    setReportStep('Rendering network diagrams…');
    try {
      // Render both ELK layouts and capture as PNG
      const diagrams = await captureNetworkDiagrams(fileId, data ?? undefined);

      setReportStep('Building PDF…');
      // POST diagrams + fileId → receive PDF blob
      const response = await apiClient.post(
        API_ENDPOINTS.REPORT_DOWNLOAD(fileId),
        { forceDirectedImage: diagrams.forceDirected, hierarchicalImage: diagrams.hierarchical },
        { responseType: 'blob' }
      );

      const url = URL.createObjectURL(new Blob([response.data], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `tracepcap-report-${fileId}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Report generation failed', e);
      setReportError('Report generation failed. Please try again.');
    } finally {
      setReportLoading(false);
      setReportStep(null);
    }
  };

  if (loading) return <AnalysisLoadingView fileId={fileId!} />;
  if (error)
    return (
      <ErrorMessage title="Failed to Load Analysis" message={error.message} onRetry={refetch} />
    );
  if (!data)
    return (
      <ErrorMessage title="No Data Available" message="No analysis data found for this file." />
    );

  return (
    <div className="analysis-page">
      {reportStep && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 10001,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <div className="card shadow-lg p-4 text-center" style={{ minWidth: 320 }}>
            <div className="spinner-border text-primary mb-3" role="status" />
            <h6 className="mb-1">Generating Report</h6>
            <p className="text-muted small mb-0">{reportStep}</p>
            <p className="text-muted small mt-1">This may take up to 60 seconds.</p>
          </div>
        </div>
      )}
      <div className="analysis-header mb-4 d-flex justify-content-between align-items-start">
        <div>
          <h2>Network Traffic Analysis</h2>
          <p className="text-muted">File ID: {fileId}</p>
        </div>
        <div className="d-flex flex-column align-items-end gap-1">
          <button
            className="btn btn-outline-primary btn-sm"
            onClick={handleDownloadReport}
            disabled={reportLoading}
          >
            {reportLoading ? (
              <>
                <span className="spinner-border spinner-border-sm me-2" role="status" />
                Generating report…
              </>
            ) : (
              <>
                <i className="bi bi-file-earmark-pdf me-2"></i>
                Download Report
              </>
            )}
          </button>
          {reportError && <small className="text-danger">{reportError}</small>}
        </div>
      </div>

      {/* Navigation Tabs */}
      <ul
        className="nav nav-tabs"
        style={{ overflowX: 'auto', overflowY: 'hidden', flexWrap: 'nowrap', display: 'flex' }}
      >
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }}
            className={`nav-link ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => handleTabChange('overview')}
          >
            <i className="bi bi-speedometer2 me-2"></i>Overview
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }}
            className={`nav-link ${activeTab === 'conversations' ? 'active' : ''}`}
            onClick={() => handleTabChange('conversations')}
          >
            <i className="bi bi-arrow-left-right me-2"></i>Conversations
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }}
            className={`nav-link ${activeTab === 'story' ? 'active' : ''}`}
            onClick={() => handleTabChange('story')}
          >
            <i className="bi bi-journal-text me-2"></i>Story
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }}
            className={`nav-link ${activeTab === 'filter-generator' ? 'active' : ''}`}
            onClick={() => handleTabChange('filter-generator')}
          >
            <i className="bi bi-funnel me-2"></i>Filter Generator
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }}
            className={`nav-link ${activeTab === 'extracted-files' ? 'active' : ''}`}
            onClick={() => handleTabChange('extracted-files')}
          >
            <i className="bi bi-file-earmark-arrow-down me-2"></i>Extracted Files
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }}
            className={`nav-link ${activeTab === 'network-diagram' ? 'active' : ''}`}
            onClick={() => handleTabChange('network-diagram')}
          >
            <i className="bi bi-diagram-3 me-2"></i>Network Diagram
          </button>
        </li>
      </ul>

      {/* Tab Content */}
      <div className="card">
        <div className="card-body">
          <Outlet context={{ data, fileId }} />
        </div>
      </div>
    </div>
  );
};
