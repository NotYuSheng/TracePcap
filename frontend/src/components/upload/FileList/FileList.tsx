import { Spinner } from '@components/common/Spinner/Spinner';
import { Link, useNavigate } from 'react-router-dom';
import { useEffect, useState, useRef, useCallback } from 'react';
import { isAxiosError } from 'axios';
import { Button, Card, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { AlertCircle } from 'lucide-react';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { Pagination } from '@components/common/Pagination/Pagination';
import { parseDateTime } from '@/utils/dateUtils';
import './FileList.css';
import { actionOf, expiresAt, notesOf, statusOf } from './fileStatus';
import { formatBytes } from '@/utils/formatters';

type MultiSelectAction = 'analyze' | 'merge';

// Exported so contractConformance.test-d.ts can check it against the backend's
// FileMetadataDto. It is a deliberate subset — this list renders only these fields.
export interface FileMetadata {
  fileId: string;
  fileName: string;
  fileSize: number;
  uploadedAt: string | number[];
  status: string;
  source?: string;
  enableNdpi?: boolean;
  enableSuricata?: boolean;
  enableFileExtraction?: boolean;
  packetCount?: number | null;
  packetsRemoved?: boolean;
}

/** "2 hours", "40 minutes": how long until a capture is deleted. */
function expiresIn(ms: number): string {
  const mins = Math.max(1, Math.round(ms / 60000));
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'}`;
  const hours = Math.round(mins / 60);
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

interface FileListProps {
  /** Rows per page to start with; the home page shows a short list. */
  defaultPageSize?: number;
}

export const FileList = ({ defaultPageSize = 25 }: FileListProps = {}) => {
  const navigate = useNavigate();
  const [files, setFiles] = useState<FileMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [pendingDeleteFile, setPendingDeleteFile] = useState<FileMetadata | null>(null);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);
  const [selectedForCompare, setSelectedForCompare] = useState<Set<string>>(new Set());
  const [selectedFileNames, setSelectedFileNames] = useState<Map<string, string>>(new Map());
  const [hideMonitor, setHideMonitor] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(defaultPageSize);
  // What the statuses need beyond the page itself: retention, network memberships, and which
  // captures the detection rules have changed for. Each is optional: without it, the list shows less.
  const [retentionHours, setRetentionHours] = useState<number | null>(null);
  const [memberships, setMemberships] = useState<Map<string, { networkId: string; networkName: string }[]>>(new Map());
  const [staleIds, setStaleIds] = useState<Set<string>>(new Set());
  const [now, setNow] = useState(() => Date.now());
  const [totalItems, setTotalItems] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
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

  // Remember the filename of every file the user has selected, so cross-page selections survive
  // even though `files` only holds the current page (server-side pagination).
  const toggleCompareSelect = (fileId: string, fileName?: string) => {
    setSelectedForCompare(prev => {
      const next = new Set(prev);
      next.has(fileId) ? next.delete(fileId) : next.add(fileId);
      return next;
    });
    if (fileName) {
      setSelectedFileNames(prev => {
        const next = new Map(prev);
        if (!next.has(fileId)) next.set(fileId, fileName);
        return next;
      });
    }
  };

  const buildAutoMergeName = (selectedIds: Set<string>): string => {
    const MAX_PART = 20;
    const MAX_SHOWN = 3;
    // Use the accumulated name map (not `files`, which is only the current page) so off-page
    // selections still contribute to the generated name.
    const names = [...selectedIds].map(id => selectedFileNames.get(id)).filter((n): n is string => !!n);
    const parts = names.slice(0, MAX_SHOWN).map(fileName => {
      const base = fileName.replace(/\.[^.]+$/, '');
      return base.length > MAX_PART ? base.slice(0, MAX_PART) : base;
    });
    const suffix = names.length > MAX_SHOWN ? `+${names.length - MAX_SHOWN}_more` : '';
    return `merged_${parts.join('+')}${suffix}`;
  };

  const handleRowClick = (fileId: string, status: string, fileName: string) => {
    if (status.toLowerCase() !== 'completed') return;
    toggleCompareSelect(fileId, fileName);
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
      setSelectedFileNames(new Map());
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

  const fetchFiles = useCallback(async () => {
    try {
      const res = await apiClient.get(API_ENDPOINTS.FILES_LIST, {
        params: {
          sort: 'uploadedAt,desc',
          page,
          pageSize,
          // ANALYSIS is the only non-monitor source, so "hide monitor" == list ANALYSIS only.
          // Omitting `source` lists everything (monitor files included).
          ...(hideMonitor ? { source: 'ANALYSIS' } : {}),
        },
      });
      setFiles(res.data.data ?? []);
      setNow(Date.now());
      setTotalItems(res.data.total ?? 0);
      setTotalPages(res.data.totalPages ?? 0);
    } catch (err) {
      console.error('Failed to fetch files:', err);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, hideMonitor]);

  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  useEffect(() => {
    apiClient
      .get<{ fileRetentionHours?: number }>(API_ENDPOINTS.SYSTEM_LIMITS)
      .then(r => setRetentionHours(r.data.fileRetentionHours ?? null))
      .catch(() => {});
    apiClient
      .get<{ fileId: string; networkId: string; networkName: string }[]>(API_ENDPOINTS.NETWORK_MEMBERSHIPS)
      .then(r => {
        const m = new Map<string, { networkId: string; networkName: string }[]>();
        for (const x of r.data) m.set(x.fileId, [...(m.get(x.fileId) ?? []), x]);
        setMemberships(m);
      })
      .catch(() => {});
    apiClient
      .get<string[]>(API_ENDPOINTS.STALE_CAPTURES)
      .then(r => setStaleIds(new Set(r.data)))
      .catch(() => {});
  }, []);


  const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)} hours ago`;

    return date.toLocaleDateString('en-GB');
  };

  const handleConfirmDelete = async () => {
    if (!pendingDeleteFile) return;
    try {
      await apiClient.delete(API_ENDPOINTS.FILE_DELETE(pendingDeleteFile.fileId));
    } catch (err) {
      // A 404 means it's already gone — treat as success and refresh either way.
      if (!(isAxiosError(err) && err.response?.status === 404)) {
        console.error('Failed to delete file:', err);
      }
    }
    setPendingDeleteFile(null);
    // If we just emptied the last page, step back; on earlier pages the rows below shift up to
    // fill the gap, so refetch in place instead of kicking the user backwards.
    if (files.length === 1 && page === totalPages && page > 1) setPage(p => p - 1);
    else fetchFiles();
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
              <Button
                type="button"
                variant="link"
                className="p-0 text-muted"
                style={{ lineHeight: 1 }}
                onClick={() => setShowInfo(v => !v)}
                aria-label="About file actions"
              >
                <i className="bi bi-info-circle" style={{ fontSize: '0.85rem' }}></i>
              </Button>
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
                  <Card.Body className="py-2 px-3">
                    <p className="mb-1">
                      <i className="bi bi-graph-up me-1 text-primary"></i>
                      Click <strong>Open</strong> on a capture to see its analysis. Each one has one status (Queued, Analysing, Ready, Expiring soon or Failed); the grey notes under its name say anything else worth knowing.
                    </p>
                    <p className="mb-0">
                      <i className="bi bi-diagram-3 me-1 text-primary"></i>
                      Select <strong>two or more</strong> files using the checkboxes, then click{' '}
                      <strong>Multi-Analysis</strong> for cross-PCAP topology analysis.
                    </p>
                  </Card.Body>
                </div>
              )}
            </div>
          </div>
          {files.length > 0 && (
            <div className="d-flex gap-2 align-items-center">
              <Button
                type="button"
                variant={hideMonitor ? 'outline-secondary' : 'secondary'}
                size="sm"
                onClick={() => setHideMonitor(v => {
                  const next = !v;
                  // New filter → back to page 1 so the current page can't fall out of range.
                  setPage(1);
                  if (next) {
                    setSelectedForCompare(prev => {
                      const monitorIds = new Set(files.filter(f => f.source === 'MONITOR').map(f => f.fileId));
                      if ([...prev].every(id => !monitorIds.has(id))) return prev;
                      const next = new Set(prev);
                      monitorIds.forEach(id => next.delete(id));
                      return next;
                    });
                  }
                  return next;
                })}
                title={hideMonitor ? 'Show monitor network files' : 'Hide monitor network files'}
              >
                <i className={`bi bi-${hideMonitor ? 'eye-slash' : 'eye'} me-1`}></i>
                Monitor files
              </Button>
              {selectedForCompare.size >= 2 && (
                <Button
                  type="button"
                  variant="outline-primary"
                  size="sm"
                  onClick={() => {
                    setMergedFileName(buildAutoMergeName(selectedForCompare));
                    setShowMultiSelectModal(true);
                  }}
                >
                  <i className="bi bi-diagram-3 me-1"></i>
                  Multi-Analysis ({selectedForCompare.size})
                </Button>
              )}
              <Button
                type="button"
                variant="outline-danger"
                size="sm"
                onClick={() => setConfirmDeleteAll(true)}
              >
                <i className="bi bi-trash me-1"></i>
                Delete page
              </Button>
            </div>
          )}
        </Card.Header>
        <Card.Body className="p-0">
          {loading ? (
            <div className="text-center text-muted py-4">
              <Spinner animation="border" size="sm" className="me-2" />
              Loading files…
            </div>
          ) : files.length === 0 ? (
            hideMonitor ? (
              <div className="text-center text-muted py-4">
                <p className="mb-0">
                  No uploads here.{' '}
                  <button
                    type="button"
                    className="btn btn-link p-0 align-baseline text-muted"
                    style={{ fontSize: 'inherit' }}
                    onClick={() => setHideMonitor(false)}
                  >
                    Show monitor files
                  </button>
                  {' '}or upload a PCAP file to get started!
                </p>
              </div>
            ) : (
              <div className="text-center text-muted py-4">
                <p className="mb-0">No uploads yet. Upload a PCAP file to get started!</p>
              </div>
            )
          ) : (
              <div className="list-group list-group-flush">
                {files.map(file => {
                  const isSelected = selectedForCompare.has(file.fileId);
                  const isCompleted = file.status.toLowerCase() === 'completed';
                  const ctx = {
                    retentionHours,
                    keptWith: memberships.get(file.fileId) ?? [],
                    rulesChanged: staleIds.has(file.fileId),
                    now,
                  };
                  const statusFile = { ...file, uploadedAt: parseDateTime(file.uploadedAt) };
                  const status = statusOf(statusFile, ctx);
                  const notes = notesOf(statusFile, ctx);
                  const expiry = expiresAt(statusFile, ctx);
                  return (
                    <div
                      key={file.fileId}
                      className="list-group-item d-flex justify-content-between align-items-center"
                      style={{
                        cursor: isCompleted ? 'pointer' : undefined,
                        backgroundColor: isSelected ? 'rgba(13,110,253,0.08)' : undefined,
                        borderLeft: isSelected ? '3px solid #0d6efd' : '3px solid transparent',
                      }}
                      role={isCompleted ? 'checkbox' : undefined}
                      aria-checked={isCompleted ? isSelected : undefined}
                      tabIndex={isCompleted ? 0 : -1}
                      onClick={() => handleRowClick(file.fileId, file.status, file.fileName)}
                      onKeyDown={e => {
                        if (!isCompleted) return;
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleRowClick(file.fileId, file.status, file.fileName);
                        }
                      }}
                    >
                      <div className="flex-grow-1 min-w-0">
                        <div className="d-flex align-items-center gap-2">
                          <i
                            className="bi bi-file-earmark-binary text-primary"
                            style={{ fontSize: '1.2rem' }}
                            aria-hidden="true"
                          ></i>
                          <div className="min-w-0">
                            <div className="fw-medium file-name">{file.fileName}</div>
                            <small className="text-muted">
                              {formatBytes(file.fileSize)}
                              {file.packetCount != null && <> · {file.packetCount.toLocaleString()} packets</>}
                              {' · '}
                              {formatDate(parseDateTime(file.uploadedAt))}
                              {status.key === 'expiring' && expiry != null && (
                                <> · deleted in {expiresIn(expiry - now)}</>
                              )}
                            </small>
                            {notes.length > 0 && (
                              <div className="file-notes" onClick={e => e.stopPropagation()}>
                                {notes.map(n =>
                                  n.to ? (
                                    <Link key={n.key} to={n.to} className={`file-note${n.tone ? ` file-note-${n.tone}` : ''}`}>
                                      {n.label}
                                    </Link>
                                  ) : (
                                    <span key={n.key} className="file-note">
                                      {n.label}
                                    </span>
                                  ),
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                      <div
                        className="d-flex gap-3 align-items-center flex-shrink-0"
                        onClick={e => e.stopPropagation()}
                      >
                        <span className={`file-status file-status-${status.key}`}>
                          <span className="file-status-dot" aria-hidden="true" />
                          {status.label}
                        </span>
                        {status.key === 'expiring' && (
                          <Link to="/monitor" className="btn btn-outline-warning btn-sm">
                            Keep it
                          </Link>
                        )}
                        <Button
                          variant={status.key === 'ready' ? 'outline-primary' : 'outline-secondary'}
                          size="sm"
                          onClick={() => navigate(`/analysis/${file.fileId}`)}
                        >
                          {actionOf(status.key)}
                        </Button>
                        <Button
                          variant="link"
                          size="sm"
                          className="p-0 text-danger"
                          onClick={() => setPendingDeleteFile(file)}
                          aria-label={`Delete ${file.fileName}`}
                        >
                          <i className="bi bi-trash"></i>
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
          )}
          {/* Show whenever the total exceeds the smallest page-size option, so the page-size
              selector stays reachable even when the current size collapses to a single page. */}
          {totalItems > 10 && (
            <div className="p-2 border-top">
              <Pagination
                currentPage={page}
                totalPages={totalPages}
                totalItems={totalItems}
                pageSize={pageSize}
                pageSizeOptions={[...new Set([defaultPageSize, 10, 25, 50, 100])].sort((a, b) => a - b)}
                onPageChange={setPage}
                onPageSizeChange={size => { setPageSize(size); setPage(1); }}
              />
            </div>
          )}
        </Card.Body>
        <Card.Footer className="text-muted small">
          <AlertCircle size={14} className="me-1" />
          Files are automatically deleted after 12 hours
          <span className="ms-2 text-muted">·</span>
          <span className="ms-2">Monitor network files are exempt and will not expire</span>
        </Card.Footer>
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
          <Button
            type="button"
            variant="outline-secondary"
            onClick={() => setPendingDeleteFile(null)}
          >
            Cancel
          </Button>
          <Button type="button" variant="outline-danger" onClick={handleConfirmDelete}>
            Delete
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Merge in-progress overlay */}
      <Modal show={merging} onHide={() => {}} centered backdrop="static" keyboard={false}>
        <Modal.Body className="text-center py-4">
          <Spinner animation="border" className="text-primary mb-3" />
          <p className="mb-0 fw-semibold">Merging files…</p>
          <small className="text-muted">This may take a moment.</small>
        </Modal.Body>
      </Modal>

      {/* Multi-select action modal */}
      <Modal
        show={showMultiSelectModal}
        onHide={() => {
          setShowMultiSelectModal(false);
          setMergeError(null);
        }}
        centered
      >
        <Modal.Header closeButton>
          <Modal.Title>Analyze {selectedForCompare.size} Files</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {mergeError && (
            <Alert variant="danger" className="py-2 mb-3">
              <i className="bi bi-exclamation-triangle me-2"></i>
              {mergeError}
            </Alert>
          )}
          <p className="mb-3">How would you like to process the selected files?</p>
          <div className="d-flex flex-column gap-3">
            <Button
              type="button"
              variant="outline-primary"
              className="text-start p-3 multiselect-action-btn"
              onClick={() => handleMultiSelectAction('analyze')}
            >
              <div className="fw-semibold mb-1">
                <i className="bi bi-diagram-3 me-2"></i>
                Analyze Together
              </div>
              <small className="text-muted">
                View a joint topology diagram overlaying all selected files. The original files
                remain separate.
              </small>
            </Button>
            <div className="border rounded p-3" style={{ borderColor: '#6c757d' }}>
              <div className="fw-semibold mb-1">
                <i className="bi bi-layers me-2"></i>
                Permanently Merge
              </div>
              <small className="text-muted d-block mb-2">
                Combine all selected files into a single new PCAP file for unified analysis.
              </small>
              <div className="input-group input-group-sm mb-2" onClick={e => e.stopPropagation()}>
                <Form.Control
                  type="text"
                  value={mergedFileName}
                  onChange={e => setMergedFileName(e.target.value)}
                  placeholder="merged file name"
                  aria-label="Merged file name"
                />
                <span className="input-group-text">.pcap</span>
              </div>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                className="w-100"
                onClick={() => handleMultiSelectAction('merge')}
                disabled={!mergedFileName.trim()}
              >
                Merge &amp; Analyze
              </Button>
            </div>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button
            type="button"
            variant="outline-secondary"
            onClick={() => {
              setShowMultiSelectModal(false);
              setMergeError(null);
            }}
          >
            Cancel
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Delete all confirmation modal */}
      <Modal show={confirmDeleteAll} onHide={() => setConfirmDeleteAll(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete Page</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p className="mb-0">
            Are you sure you want to delete the <strong>{files.length}</strong> file
            {files.length !== 1 ? 's' : ''} on this page?
            {totalItems > files.length && (
              <span className="d-block text-muted small mt-1">
                Only this page is affected — {totalItems - files.length} more remain on other pages.
              </span>
            )}
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button
            type="button"
            variant="outline-secondary"
            onClick={() => setConfirmDeleteAll(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="danger"
            onClick={async () => {
              await Promise.allSettled(
                files.map(f => apiClient.delete(API_ENDPOINTS.FILE_DELETE(f.fileId)))
              );
              setConfirmDeleteAll(false);
              // Only step back if we emptied the last page; earlier pages backfill from below.
              if (page === totalPages && page > 1) setPage(p => p - 1);
              else fetchFiles();
            }}
          >
            Delete page
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};
