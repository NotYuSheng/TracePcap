import { useNavigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { isAxiosError } from 'axios';
import { Card, Modal } from '@govtechsg/sgds-react';
import { AlertCircle } from 'lucide-react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import './FileList.css';

interface FileMetadata {
  fileId: string;
  fileName: string;
  fileSize: number;
  uploadedAt: string | number[];
  status: string;
}

export const FileList = () => {
  const navigate = useNavigate();
  const [files, setFiles] = useState<FileMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [pendingDeleteFile, setPendingDeleteFile] = useState<FileMetadata | null>(null);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);

  const fetchFiles = async () => {
    try {
      const res = await apiClient.get(API_ENDPOINTS.FILES_LIST, {
        params: { sort: 'uploadedAt,desc', size: 50 },
      });
      setFiles(res.data.content ?? []);
    } catch (err) {
      console.error('Failed to fetch files:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
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

  const handleConfirmDelete = async () => {
    if (!pendingDeleteFile) return;
    try {
      await apiClient.delete(API_ENDPOINTS.FILE_DELETE(pendingDeleteFile.fileId));
      setFiles(prev => prev.filter(f => f.fileId !== pendingDeleteFile.fileId));
    } catch (err) {
      if (isAxiosError(err) && err.response?.status === 404) {
        setFiles(prev => prev.filter(f => f.fileId !== pendingDeleteFile.fileId));
      } else {
        console.error('Failed to delete file:', err);
      }
    }
    setPendingDeleteFile(null);
  };

  return (
    <>
      <Card className="file-list-card mt-4">
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">
            <i className="bi bi-folder2-open me-2"></i>
            All Uploads
          </h5>
          {files.length > 0 && (
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
          {loading ? (
            <div className="text-center text-muted py-4">
              <div
                className="spinner-border spinner-border-sm me-2"
                role="status"
                aria-hidden="true"
              />
              Loading files…
            </div>
          ) : files.length === 0 ? (
            <div className="text-center text-muted py-4">
              <p className="mb-0">No uploads yet. Upload a PCAP file to get started!</p>
            </div>
          ) : (
            <div
              className="list-group list-group-flush"
              style={{ maxHeight: '13.5rem', overflowY: 'auto' }}
            >
              {files.map(file => (
                <div
                  key={file.fileId}
                  className="list-group-item list-group-item-action d-flex justify-content-between align-items-center"
                  style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/analysis/${file.fileId}`)}
                >
                  <div className="flex-grow-1">
                    <div className="d-flex align-items-center gap-2">
                      <i
                        className="bi bi-file-earmark-binary text-primary"
                        style={{ fontSize: '1.2rem' }}
                      ></i>
                      <div>
                        <div className="fw-medium">{file.fileName}</div>
                        <small className="text-muted">
                          {formatFileSize(file.fileSize)} •{' '}
                          {formatDate(parseDateTime(file.uploadedAt))}
                          {file.status.toLowerCase() !== 'completed' && (
                            <span
                              className="ms-2 badge bg-secondary"
                              style={{ fontSize: '0.7rem' }}
                            >
                              {file.status.toLowerCase()}
                            </span>
                          )}
                        </small>
                      </div>
                    </div>
                  </div>
                  <div className="d-flex gap-2 align-items-center">
                    <button
                      className="btn btn-outline-primary btn-sm"
                      onClick={e => {
                        e.stopPropagation();
                        navigate(`/analysis/${file.fileId}`);
                      }}
                    >
                      <i className="bi bi-graph-up me-1"></i>
                      Analyze
                    </button>
                    <button
                      className="btn btn-link btn-sm p-0 text-danger"
                      onClick={e => {
                        e.stopPropagation();
                        setPendingDeleteFile(file);
                      }}
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
            Are you sure you want to delete <strong>{pendingDeleteFile?.fileName}</strong>?
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
            Are you sure you want to delete all <strong>{files.length}</strong> uploaded files?
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
            onClick={async () => {
              const results = await Promise.allSettled(
                files.map(f => apiClient.delete(API_ENDPOINTS.FILE_DELETE(f.fileId)))
              );
              const deletedIds = new Set(
                results
                  .map((r, i) => (r.status === 'fulfilled' ? files[i].fileId : null))
                  .filter(Boolean)
              );
              setFiles(prev => prev.filter(f => !deletedIds.has(f.fileId)));
              setConfirmDeleteAll(false);
            }}
          >
            Delete all
          </button>
        </Modal.Footer>
      </Modal>
    </>
  );
};
