import { useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import { Card } from '@govtechsg/sgds-react';
import { AlertCircle } from 'lucide-react';
import { useStore } from '@/store';
import type { RecentFile } from '@/store/slices/uploadSlice';
import './FileList.css';

export const FileList = () => {
  const recentFiles = useStore(state => state.recentFiles);
  const removeRecentFile = useStore(state => state.removeRecentFile);
  const navigate = useNavigate();

  // Validate files on mount - remove files that no longer exist on backend
  useEffect(() => {
    const validateFiles = async () => {
      const filesToValidate = [...recentFiles]; // Copy array to avoid stale closures
      for (const file of filesToValidate) {
        try {
          const response = await fetch(`http://localhost:8080/api/files/${file.id}`);
          if (response.status === 404) {
            // File doesn't exist on backend, remove from localStorage
            console.log(`File ${file.name} no longer exists on backend, removing from recent files`);
            removeRecentFile(file.id);
          } else if (!response.ok) {
            console.warn(`Unexpected status ${response.status} for file ${file.name}`);
          }
        } catch (error) {
          // Network error or backend down, keep the file in the list
          console.warn(`Could not validate file ${file.name}:`, error);
        }
      }
    };

    const hasFilesToValidate = recentFiles.length > 0;
    if (hasFilesToValidate) {
      validateFiles();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Only run once on mount - removeRecentFile is stable

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)} hours ago`;

    return date.toLocaleDateString();
  };

  const handleFileClick = (file: RecentFile) => {
    navigate(`/analysis/${file.id}`);
  };

  const handleRemoveFile = (fileId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    removeRecentFile(fileId);
  };

  return (
    <Card className="file-list-card mt-4">
      <Card.Header>
        <h5 className="mb-0">
          <i className="bi bi-clock-history me-2"></i>
          Recent Uploads
        </h5>
      </Card.Header>
      <Card.Body className="p-0">
        {recentFiles.length === 0 ? (
          <div className="text-center text-muted py-4">
            <p className="mb-0">No recent uploads. Upload a PCAP file to get started!</p>
          </div>
        ) : (
          <div className="list-group list-group-flush">
            {recentFiles.map(file => (
              <div
                key={file.id}
                className="list-group-item list-group-item-action d-flex justify-content-between align-items-center"
                style={{ cursor: 'pointer' }}
                onClick={() => handleFileClick(file)}
              >
                <div className="flex-grow-1">
                  <div className="d-flex align-items-center gap-2">
                    <i
                      className="bi bi-file-earmark-binary text-primary"
                      style={{ fontSize: '1.2rem' }}
                    ></i>
                    <div>
                      <div className="fw-medium">{file.name}</div>
                      <small className="text-muted">
                        {formatFileSize(file.size)} • {formatDate(file.uploadedAt)}
                      </small>
                    </div>
                  </div>
                </div>
                <div className="d-flex gap-2 align-items-center">
                  <button
                    className="btn btn-outline-primary btn-sm"
                    onClick={e => {
                      e.stopPropagation();
                      handleFileClick(file);
                    }}
                  >
                    <i className="bi bi-graph-up me-1"></i>
                    Analyze
                  </button>
                  <button
                    className="btn btn-link btn-sm p-0 text-danger"
                    onClick={e => handleRemoveFile(file.id, e)}
                    title="Delete this file"
                  >
                    <i className="bi bi-trash"></i>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="card-footer text-muted small">
          <AlertCircle size={14} className="me-1" />
          Files are automatically deleted after 12 hours
        </div>
      </Card.Body>
    </Card>
  );
};
