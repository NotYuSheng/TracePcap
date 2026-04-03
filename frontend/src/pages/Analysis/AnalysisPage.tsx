import { useState, useEffect } from 'react';
import { useParams, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAnalysisData } from '@features/analysis/hooks/useAnalysisData';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { AnalysisLoadingView } from './AnalysisLoadingView';

export const AnalysisPage = () => {
  const { fileId } = useParams<{ fileId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { data, loading, error, refetch } = useAnalysisData(fileId!);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Determine active tab from URL
    const path = location.pathname;
    if (path.includes('/conversations')) {
      setActiveTab('conversations');
    } else if (path.includes('/story')) {
      setActiveTab('story');
    } else if (path.includes('/filter-generator')) {
      setActiveTab('filter-generator');
    } else if (path.includes('/network-diagram')) {
      setActiveTab('network-diagram');
    } else if (path.includes('/extracted-files')) {
      setActiveTab('extracted-files');
    } else {
      setActiveTab('overview');
    }
  }, [location.pathname]);

  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
    if (tab === 'overview') {
      navigate(`/analysis/${fileId}`);
    } else {
      navigate(`/analysis/${fileId}/${tab}`);
    }
  };

  if (loading) {
    return <AnalysisLoadingView fileId={fileId!} />;
  }

  if (error) {
    return (
      <ErrorMessage title="Failed to Load Analysis" message={error.message} onRetry={refetch} />
    );
  }

  if (!data) {
    return (
      <ErrorMessage title="No Data Available" message="No analysis data found for this file." />
    );
  }

  return (
    <div className="analysis-page">
      <div className="analysis-header mb-4">
        <h2>Network Traffic Analysis</h2>
        <p className="text-muted">File ID: {fileId}</p>
      </div>

      {/* Navigation Tabs */}
      <ul className="nav nav-tabs" style={{ overflowX: 'auto', overflowY: 'hidden', flexWrap: 'nowrap', display: 'flex' }}>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }} className={`nav-link ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => handleTabChange('overview')}
          >
            <i className="bi bi-speedometer2 me-2"></i>
            Overview
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }} className={`nav-link ${activeTab === 'conversations' ? 'active' : ''}`}
            onClick={() => handleTabChange('conversations')}
          >
            <i className="bi bi-arrow-left-right me-2"></i>
            Conversations
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }} className={`nav-link ${activeTab === 'story' ? 'active' : ''}`}
            onClick={() => handleTabChange('story')}
          >
            <i className="bi bi-journal-text me-2"></i>
            Story
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }} className={`nav-link ${activeTab === 'filter-generator' ? 'active' : ''}`}
            onClick={() => handleTabChange('filter-generator')}
          >
            <i className="bi bi-funnel me-2"></i>
            Filter Generator
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }} className={`nav-link ${activeTab === 'extracted-files' ? 'active' : ''}`}
            onClick={() => handleTabChange('extracted-files')}
          >
            <i className="bi bi-file-earmark-arrow-down me-2"></i>
            Extracted Files
          </button>
        </li>
        <li className="nav-item">
          <button
            style={{ whiteSpace: 'nowrap' }} className={`nav-link ${activeTab === 'network-diagram' ? 'active' : ''}`}
            onClick={() => handleTabChange('network-diagram')}
          >
            <i className="bi bi-diagram-3 me-2"></i>
            Network Diagram
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
