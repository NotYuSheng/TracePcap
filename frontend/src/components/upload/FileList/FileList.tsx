import { useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { isAxiosError } from 'axios';
import { Card, Modal } from '@govtechsg/sgds-react';
import { AlertCircle } from 'lucide-react';
import { useStore } from '@/store';
import type { RecentFile } from '@/store/slices/uploadSlice';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import './FileList.css';

export const FileList = () => {
  const recentFiles = useStore(state => state.recentFiles);
  const removeRecentFile = useStore(state => state.removeRecentFile);
  const clearRecentFiles = useStore(state => state.clearRecentFiles);
  const navigate = useNavigate();
  const [pendingDeleteFile, setPendingDeleteFile] = useState<RecentFile | null>(null);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);

  // Validate files on mount - remove files that no longer exist on backend
  useEffect(() => {
    const validateFiles = async () => {
      const { recentFiles, removeRecentFile } = useStore.getState();
      for (const file of recentFiles) {
        try {
          await apiClient.get(API_ENDPOINTS.FILE_METADATA(file.id));
        } catch (error: unknown) {
          if (isAxiosError(error)) {
            const status = error.response?.status;
            if (status === 404) {
              removeRecentFile(file.id);
            } else if (status !== undefined) {
              console.warn(`Unexpected status ${status} for file ${file.name}`);
            }
          }
          // Network error or backend down — keep file in list
        }
      }
    };

    if (useStore.getState().recentFiles.length > 0) {
      validateFiles();
    }
  }, []);

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

  const handleDeleteClick = (file: RecentFile, e: React.MouseEvent) => {
    e.stopPropagation();
    setPendingDeleteFile(file);
  };

  const handleConfirmDelete = () => {
    if (pendingDeleteFile) {
      removeRecentFile(pendingDeleteFile.id);
      setPendingDeleteFile(null);
    }
  };

  return (
    <>
      <Card className="file-list-card mt-4">
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">
            <i className="bi bi-clock-history me-2"></i>
            Recent Uploads
          </h5>
          {recentFiles.length > 0 && (
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              onClick={() => setConfirmDeleteAll(true)}
            >
              <i className="bi bi-trash me-1"></i>
              Delete all
            </button>
          )}
        </Card.Header>
        <Card.Body className="p-0">
          {recentFiles.length === 0 ? (
            <div className="text-center text-muted py-4">
              <p className="mb-0">No recent uploads. Upload a PCAP file to get started!</p>
            </div>
          ) : (
            <div className="list-group list-group-flush" style={{ maxHeight: '13.5rem', overflowY: 'auto' }}>
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
                      onClick={e => handleDeleteClick(file, e)}
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

      {/* Delete confirmation modal */}
      <Modal show={!!pendingDeleteFile} onHide={() => setPendingDeleteFile(null)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete File</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-0">
            Are you sure you want to remove <strong>{pendingDeleteFile?.name}</strong> from your
            recent uploads?
          </p>
        </Modal.Body>
        <Modal.Footer>
          <button
            type="button"
            className="btn btn-outline-secondary"
            onClick={() => setPendingDeleteFile(null)}
          >
            Cancel
          </button>
          <button type="button" className="btn btn-outline-danger" onClick={handleConfirmDelete}>
            Delete
          </button>
        </Modal.Footer>
      </Modal>

      {/* Delete all confirmation modal */}
      <Modal show={confirmDeleteAll} onHide={() => setConfirmDeleteAll(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete All</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-0">
            Are you sure you want to remove all <strong>{recentFiles.length}</strong> recent uploads?
          </p>
        </Modal.Body>
        <Modal.Footer>
          <button
            type="button"
            className="btn btn-outline-secondary"
            onClick={() => setConfirmDeleteAll(false)}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => { clearRecentFiles(); setConfirmDeleteAll(false); }}
          >
            Delete all
          </button>
        </Modal.Footer>
      </Modal>
    </>
  );
};
