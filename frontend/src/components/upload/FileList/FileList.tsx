import { useNavigate } from 'react-router-dom';
import { useEffect, useState, useRef } from 'react';
import { isAxiosError } from 'axios';
import { Card, Modal } from '@govtechsg/sgds-react';
import { AlertCircle } from 'lucide-react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import './FileList.css';

type MultiSelectAction = 'analyze' | 'merge';

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
  const [selectedForCompare, setSelectedForCompare] = useState<Set<string>>(new Set());
  const [showInfo, setShowInfo] = useState(false);
  const [showMultiSelectModal, setShowMultiSelectModal] = useState(false);
  const [merging, setMerging] = useState(false);
  const [mergeError, setMergeError] = useState<string | null>(null);
  const [mergedFileName, setMergedFileName] = useState('');
  const infoRef = useRef<HTMLDivElement>(null);

  // Close info popover when clicking outside
  useEffect(() => {
    if (!showInfo) return;
    const handler = (e: MouseEvent) => {
      if (infoRef.current && !infoRef.current.contains(e.target as Node)) {
        setShowInfo(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showInfo]);

  const toggleCompareSelect = (fileId: string) =>
    setSelectedForCompare(prev => {
      const next = new Set(prev);
      next.has(fileId) ? next.delete(fileId) : next.add(fileId);
      return next;
    });

  const buildAutoMergeName = (selectedIds: Set<string>): string => {
    const MAX_PART = 20;
    const MAX_SHOWN = 3;
    const selected = files.filter(f => selectedIds.has(f.fileId));
    const parts = selected.slice(0, MAX_SHOWN).map(f => {
      const base = f.fileName.replace(/\.[^.]+$/, '');
      return base.length > MAX_PART ? base.slice(0, MAX_PART) : base;
    });
    const suffix = selected.length > MAX_SHOWN ? `+${selected.length - MAX_SHOWN}_more` : '';
    return `merged_${parts.join('+')}${suffix}`;
  };

  const handleRowClick = (fileId: string, status: string) => {
    if (status.toLowerCase() !== 'completed') return;
    toggleCompareSelect(fileId);
  };

  const handleMultiSelectAction = async (action: MultiSelectAction) => {
    setShowMultiSelectModal(false);
    if (action === 'analyze') {
      navigate(`/compare?files=${[...selectedForCompare].join(',')}`);
      return;
    }

    // Permanently merge
    setMergeError(null);
    setMerging(true);
    try {
      const name = mergedFileName.trim() || buildAutoMergeName(selectedForCompare);
      const res = await apiClient.post(API_ENDPOINTS.FILES_MERGE, {
        fileIds: [...selectedForCompare],
        mergedFileName: name.endsWith('.pcap') ? name : `${name}.pcap`,
      });
      const newFileId: string = res.data.fileId;
      setSelectedForCompare(new Set());
      navigate(`/analysis/${newFileId}`);
    } catch (err) {
      const message =
        isAxiosError(err) && err.response?.data?.message
          ? err.response.data.message
          : 'Failed to merge files. Please try again.';
      setMergeError(message);
    } finally {
      setMerging(false);
    }
  };

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
          <div className="d-flex align-items-center gap-1">
            <h5 className="mb-0">
              <i className="bi bi-folder2-open me-2"></i>
              All Uploads
            </h5>
            <div ref={infoRef} style={{ position: 'relative' }}>
              <button
                type="button"
                className="btn btn-link p-0 text-muted"
                style={{ lineHeight: 1 }}
                onClick={() => setShowInfo(v => !v)}
                aria-label="About file actions"
              >
                <i className="bi bi-info-circle" style={{ fontSize: '0.85rem' }}></i>
              </button>
              {showInfo && (
                <div
                  className="card shadow"
                  style={{
                    position: 'absolute',
                    top: '1.6rem',
                    left: 0,
                    zIndex: 100,
                    width: '260px',
                    fontSize: '0.82rem',
                  }}
                >
                  <div className="card-body py-2 px-3">
                    <p className="mb-1">
                      <i className="bi bi-graph-up me-1 text-primary"></i>
                      Click <strong>Analyze</strong> on any file to open its individual analysis.
                    </p>
                    <p className="mb-0">
                      <i className="bi bi-diagram-3 me-1 text-primary"></i>
                      Select <strong>two or more</strong> files using the checkboxes, then click <strong>Compare selected</strong> for cross-PCAP topology analysis.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
          {files.length > 0 && (
            <div className="d-flex gap-2">
              {selectedForCompare.size >= 2 && (
                <button
                  type="button"
                  className="btn btn-outline-primary btn-sm"
                  onClick={() => {
                    setMergedFileName(buildAutoMergeName(selectedForCompare));
                    setShowMultiSelectModal(true);
                  }}
                >
                  <i className="bi bi-diagram-3 me-1"></i>
                  Compare selected ({selectedForCompare.size})
                </button>
              )}
              <button
                type="button"
                className="btn btn-outline-danger btn-sm"
                onClick={() => setConfirmDeleteAll(true)}
              >
                <i className="bi bi-trash me-1"></i>
                Delete all
              </button>
            </div>
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
                  className="list-group-item d-flex justify-content-between align-items-center"
                  style={file.status.toLowerCase() === 'completed' ? { cursor: 'pointer' } : undefined}
                  onClick={() => handleRowClick(file.fileId, file.status)}
                >
                  <div className="flex-grow-1">
                    <div className="d-flex align-items-center gap-2">
                      <input
                        type="checkbox"
                        className="form-check-input mt-0 flex-shrink-0"
                        checked={selectedForCompare.has(file.fileId)}
                        disabled={file.status.toLowerCase() !== 'completed'}
                        title={
                          file.status.toLowerCase() !== 'completed'
                            ? 'File must be fully processed to compare'
                            : 'Select for comparison'
                        }
                        onChange={() => toggleCompareSelect(file.fileId)}
                        onClick={e => e.stopPropagation()}
                      />
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
                  <div className="d-flex gap-2 align-items-center" onClick={e => e.stopPropagation()}>
                    <button
                      className="btn btn-outline-primary btn-sm"
                      onClick={() => navigate(`/analysis/${file.fileId}`)}
                    >
                      <i className="bi bi-graph-up me-1"></i>
                      Analyze
                    </button>
                    <button
                      className="btn btn-link btn-sm p-0 text-danger"
                      onClick={() => setPendingDeleteFile(file)}
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

      {/* Merge in-progress overlay */}
      <Modal show={merging} onHide={() => {}} centered backdrop="static" keyboard={false}>
        <Modal.Body className="text-center py-4">
          <div className="spinner-border text-primary mb-3" role="status" aria-hidden="true" />
          <p className="mb-0 fw-semibold">Merging files…</p>
          <small className="text-muted">This may take a moment.</small>
        </Modal.Body>
      </Modal>

      {/* Multi-select action modal */}
      <Modal show={showMultiSelectModal} onHide={() => { setShowMultiSelectModal(false); setMergeError(null); }} centered>
        <Modal.Header closeButton>
          <Modal.Title>Analyze {selectedForCompare.size} Files</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {mergeError && (
            <div className="alert alert-danger py-2 mb-3" role="alert">
              <i className="bi bi-exclamation-triangle me-2"></i>
              {mergeError}
            </div>
          )}
          <p className="mb-3">How would you like to process the selected files?</p>
          <div className="d-flex flex-column gap-3">
            <button
              type="button"
              className="btn btn-outline-primary text-start p-3 multiselect-action-btn"
              onClick={() => handleMultiSelectAction('analyze')}
            >
              <div className="fw-semibold mb-1">
                <i className="bi bi-diagram-3 me-2"></i>
                Analyze Together
              </div>
              <small className="text-muted">
                View a joint topology diagram overlaying all selected files. The original files remain separate.
              </small>
            </button>
            <div className="border rounded p-3" style={{ borderColor: '#6c757d' }}>
              <div className="fw-semibold mb-1">
                <i className="bi bi-layers me-2"></i>
                Permanently Merge
              </div>
              <small className="text-muted d-block mb-2">
                Combine all selected files into a single new PCAP file for unified analysis.
              </small>
              <div className="input-group input-group-sm mb-2" onClick={e => e.stopPropagation()}>
                <input
                  type="text"
                  className="form-control"
                  value={mergedFileName}
                  onChange={e => setMergedFileName(e.target.value)}
                  placeholder="merged file name"
                  aria-label="Merged file name"
                />
                <span className="input-group-text">.pcap</span>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm w-100"
                onClick={() => handleMultiSelectAction('merge')}
                disabled={!mergedFileName.trim()}
              >
                Merge &amp; Analyze
              </button>
            </div>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <button
            type="button"
            className="btn btn-outline-secondary"
            onClick={() => { setShowMultiSelectModal(false); setMergeError(null); }}
          >
            Cancel
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
