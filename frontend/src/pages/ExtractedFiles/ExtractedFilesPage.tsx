import { useState, useEffect, useCallback, useMemo } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import {
  getExtractedFiles,
  getDownloadUrl,
  getPreviewUrl,
  type ExtractedFile,
} from '@features/extractedFiles/services/extractedFilesService';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { ScrollableTable } from '@components/common/ScrollableTable';
import { PillSectionHeader } from '@components/common/PillSectionHeader/PillSectionHeader';
import { Modal } from '@govtechsg/sgds-react';
import { formatBytes } from '@/utils/formatters';
import '@components/conversation/ConversationFilterPanel/ConversationFilterPanel.css';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

type SortField = 'filename' | 'mimeType' | 'fileSize' | 'extractionMethod';
type SortDir = 'asc' | 'desc';

const ExtractionInfoCard = () => {
  const [collapsed, setCollapsed] = useState(true);
  return (
    <div className="card mb-3" style={{ overflow: 'hidden' }}>
      <div
        className="card-header d-flex align-items-center justify-content-between"
        style={{
          cursor: 'pointer',
          userSelect: 'none',
          borderBottom: collapsed ? 'none' : undefined,
        }}
        onClick={() => setCollapsed(c => !c)}
      >
        <h6 className="mb-0">
          <i className="bi bi-info-circle me-2"></i>
          What's listed here &amp; how files are extracted
        </h6>
        <i className={`bi bi-chevron-${collapsed ? 'down' : 'up'} text-muted`}></i>
      </div>
      {!collapsed && (
        <div className="card-body small text-muted">
          <p className="mb-2">Files are extracted using two methods:</p>
          <ul className="mb-3">
            <li>
              <strong>HTTP</strong> — tshark's <code>--export-objects http</code> exports HTTP
              objects from the capture, including GET response bodies, POST request bodies, and POST
              response bodies. This covers images, documents, HTML pages, scripts, ad-tracking
              payloads, and anything else transferred over HTTP. Use the <strong>MIME type</strong>{' '}
              column to identify what each entry actually is. Where the source TCP stream can be
              determined, a link to the originating conversation is shown.
            </li>
            <li>
              <strong>Raw stream</strong> — for non-HTTP conversations, the TCP/UDP stream is
              reconstructed and scanned in a single pass using an Aho-Corasick automaton built from
              known file magic bytes. Candidate positions are then confirmed with Apache Tika's MIME
              detection. Any byte range matching a known file signature is extracted and stored with
              its detected MIME type.
            </li>
          </ul>
          <p className="mb-0">
            All extracted files are stored as raw bytes only — no execution or active-content
            rendering occurs. A safety disclaimer is shown before each download. Individual files
            larger than 50 MB are not stored; they appear in this list with a{' '}
            <span className="badge bg-warning text-dark" style={{ fontSize: '0.85em' }}>Too large</span>{' '}
            badge so you can see they were detected but skipped.
          </p>
        </div>
      )}
    </div>
  );
};

function mimeIcon(mimeType: string | null): string {
  if (!mimeType) return 'bi-file-earmark';
  if (mimeType.startsWith('image/')) return 'bi-file-earmark-image';
  if (mimeType === 'application/pdf') return 'bi-file-earmark-pdf';
  if (mimeType.includes('zip') || mimeType.includes('gzip') || mimeType.includes('compressed'))
    return 'bi-file-earmark-zip';
  if (mimeType.includes('msdownload') || mimeType.includes('dosexec') || mimeType.includes('elf'))
    return 'bi-file-earmark-binary';
  return 'bi-file-earmark';
}

/**
 * Returns the preview mode for a MIME type if the browser can play it natively, or null otherwise.
 * Only audio/video/image types that are universally supported without plugins are included.
 */
function nativePreviewMode(mimeType: string | null): 'audio' | 'video' | 'image' | null {
  if (!mimeType) return null;
  // Images — always natively renderable
  if (mimeType === 'image/jpeg' || mimeType === 'image/png' || mimeType === 'image/gif'
      || mimeType === 'image/webp' || mimeType === 'image/svg+xml') return 'image';
  // Audio — widely supported
  if (mimeType === 'audio/mpeg' || mimeType === 'audio/mp3' || mimeType === 'audio/wav'
      || mimeType === 'audio/ogg' || mimeType === 'audio/flac' || mimeType === 'audio/aac'
      || mimeType === 'audio/webm' || mimeType === 'audio/mp4') return 'audio';
  // Video — widely supported
  if (mimeType === 'video/mp4' || mimeType === 'video/webm' || mimeType === 'video/ogg') return 'video';
  return null;
}

function methodBadge(method: string | null) {
  if (method === 'tshark_http') return <span className="badge bg-primary">HTTP</span>;
  if (method === 'magic_bytes') return <span className="badge bg-secondary">Raw stream</span>;
  return <span className="badge bg-light text-dark">{method ?? '—'}</span>;
}

function sortFiles(files: ExtractedFile[], by: SortField | '', dir: SortDir): ExtractedFile[] {
  if (!by) return files;
  return [...files].sort((a, b) => {
    let cmp = 0;
    if (by === 'filename') cmp = (a.filename ?? '').localeCompare(b.filename ?? '');
    else if (by === 'mimeType') cmp = (a.mimeType ?? '').localeCompare(b.mimeType ?? '');
    else if (by === 'fileSize') cmp = (a.fileSize ?? 0) - (b.fileSize ?? 0);
    else if (by === 'extractionMethod')
      cmp = (a.extractionMethod ?? '').localeCompare(b.extractionMethod ?? '');
    return dir === 'asc' ? cmp : -cmp;
  });
}

const CopyHash = ({ hash }: { hash: string }) => {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [hash]);
  return (
    <span className="d-inline-flex align-items-center gap-1">
      <span className="font-monospace text-muted" style={{ fontSize: '0.75em' }} title={hash}>
        {hash.substring(0, 8)}…{hash.substring(hash.length - 8)}
      </span>
      <button
        className="btn btn-link btn-sm p-0 text-muted"
        style={{ fontSize: '0.75em', lineHeight: 1 }}
        onClick={copy}
        title={copied ? 'Copied!' : 'Copy full hash'}
      >
        <i className={`bi ${copied ? 'bi-check text-success' : 'bi-clipboard'}`}></i>
      </button>
    </span>
  );
};

export const ExtractedFilesPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const navigate = useNavigate();
  const [files, setFiles] = useState<ExtractedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pendingDownload, setPendingDownload] = useState<ExtractedFile | null>(null);
  const [previewFile, setPreviewFile] = useState<ExtractedFile | null>(null);
  const [sortBy, setSortBy] = useState<SortField | ''>('');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [mimeTypeFilter, setMimeTypeFilter] = useState<string[]>([]);
  const [filterOpen, setFilterOpen] = useState(false);

  const allMimeTypes = useMemo(
    () =>
      [...new Set(files.map(f => f.mimeType).filter((m): m is string => m !== null))].sort(),
    [files]
  );

  useEffect(() => {
    setLoading(true);
    getExtractedFiles(fileId)
      .then(setFiles)
      .catch(err => setError(err?.message ?? 'Failed to load extracted files'))
      .finally(() => setLoading(false));
  }, [fileId]);

  const handleSort = (field: SortField) => {
    if (sortBy !== field) {
      setSortBy(field);
      setSortDir('asc');
    } else if (sortDir === 'asc') {
      setSortDir('desc');
    } else {
      setSortBy('');
      setSortDir('asc');
    }
  };

  const SortableHeader = ({ field, label }: { field: SortField; label: string }) => {
    const isActive = sortBy === field;
    const icon = !isActive
      ? 'bi-arrow-down-up text-muted'
      : sortDir === 'asc'
        ? 'bi-sort-up'
        : 'bi-sort-down';
    return (
      <th
        onClick={() => handleSort(field)}
        style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
      >
        {label} <i className={`bi ${icon} ms-1`}></i>
      </th>
    );
  };

  const handleDownloadRequest = (file: ExtractedFile) => setPendingDownload(file);

  const confirmDownload = () => {
    if (!pendingDownload) return;
    const url = getDownloadUrl(fileId, pendingDownload.id);
    const a = document.createElement('a');
    a.href = url;
    a.download = pendingDownload.filename ?? 'extracted-file';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setPendingDownload(null);
  };

  if (loading) return <LoadingSpinner message="Loading extracted files…" />;
  if (error) return <ErrorMessage title="Failed to load extracted files" message={error} />;

  const filtered =
    mimeTypeFilter.length > 0
      ? files.filter(f => f.mimeType !== null && mimeTypeFilter.includes(f.mimeType))
      : files;
  const sorted = sortFiles(filtered, sortBy, sortDir);

  return (
    <div>
      <div className="d-flex align-items-center justify-content-between mb-3">
        <div>
          <h5 className="mb-0">Extracted Files</h5>
          <small className="text-muted">
            Files detected and extracted from HTTP transfers and raw packet streams.
          </small>
        </div>
        <span className="badge bg-secondary fs-6">
          {mimeTypeFilter.length > 0
            ? `${sorted.length} / ${files.length}`
            : files.length}{' '}
          file{files.length !== 1 ? 's' : ''}
        </span>
      </div>

      <ExtractionInfoCard />

      {/* Filter panel */}
      {allMimeTypes.length > 0 && (
        <div className="conversation-filter-panel mb-3">
          <div className="d-flex align-items-center gap-2">
            <button
              type="button"
              className="btn btn-outline-secondary btn-sm"
              onClick={() => setFilterOpen(o => !o)}
            >
              <i className="bi bi-funnel me-1"></i>
              Filters
              {mimeTypeFilter.length > 0 && (
                <span className="badge bg-primary ms-2">{mimeTypeFilter.length}</span>
              )}
              <i className={`bi ms-2 ${filterOpen ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
            </button>
          </div>
          {filterOpen && (
            <div className="card mt-2 filter-panel-body">
              <div className="card-body p-3">
                <PillSectionHeader
                  label="MIME Type"
                  onSelectAll={() => setMimeTypeFilter(allMimeTypes)}
                  onDeselectAll={() => setMimeTypeFilter([])}
                />
                <div className="d-flex flex-wrap gap-1">
                  {allMimeTypes.map(mt => {
                    const isActive = mimeTypeFilter.includes(mt);
                    return (
                      <button
                        key={mt}
                        type="button"
                        className={`badge rounded-pill border-0 filter-pill ${isActive ? 'active' : ''}`}
                        onClick={() =>
                          setMimeTypeFilter(prev =>
                            prev.includes(mt) ? prev.filter(v => v !== mt) : [...prev, mt]
                          )
                        }
                      >
                        <i className={`bi ${mimeIcon(mt)} me-1`}></i>
                        {mt}
                      </button>
                    );
                  })}
                </div>
                {mimeTypeFilter.length > 0 && (
                  <div className="mt-3 pt-2 border-top">
                    <button
                      type="button"
                      className="btn btn-sm btn-outline-secondary"
                      onClick={() => setMimeTypeFilter([])}
                    >
                      <i className="bi bi-x-circle me-1"></i>Clear filters
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="card">
        <div className="card-header d-flex justify-content-between align-items-center">
          <h6 className="mb-0">Files</h6>
          <small className="text-muted">Click a column header to sort</small>
        </div>
        <div className="card-body p-0" style={{ position: 'relative' }}>
          {sorted.length === 0 ? (
            <div className="text-center py-5 text-muted">
              <i className="bi bi-inbox fs-1 d-block mb-2"></i>
              {mimeTypeFilter.length > 0
                ? 'No files match the selected MIME type filter.'
                : 'No files were extracted from this capture.'}
            </div>
          ) : (
            <ScrollableTable>
              <table className="table table-hover mb-0">
                <thead>
                  <tr>
                    <SortableHeader field="filename" label="Filename" />
                    <SortableHeader field="mimeType" label="MIME type" />
                    <SortableHeader field="fileSize" label="Size" />
                    <th>SHA-256</th>
                    <th>Conversation</th>
                    <SortableHeader field="extractionMethod" label="Method" />
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map(file => {
                    const isSkipped = file.skippedReason != null;
                    return (
                    <tr key={file.id} className={isSkipped ? 'text-muted' : undefined}>
                      <td>
                        <i className={`bi ${mimeIcon(file.mimeType)} me-2 text-secondary`}></i>
                        <span className="font-monospace" style={{ fontSize: '0.85em' }}>
                          {file.filename ?? '(unnamed)'}
                        </span>
                      </td>
                      <td>
                        <span className="text-muted" style={{ fontSize: '0.85em' }}>
                          {file.mimeType ?? '—'}
                        </span>
                      </td>
                      <td className="text-nowrap">
                        {file.fileSize != null ? formatBytes(file.fileSize) : '—'}
                      </td>
                      <td>
                        {file.sha256 ? (
                          <CopyHash hash={file.sha256} />
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td>
                        {file.conversationId ? (
                          <button
                            className="btn btn-link btn-sm p-0"
                            style={{ fontSize: '0.8em' }}
                            onClick={() =>
                              navigate(
                                `/analysis/${fileId}/conversations?highlight=${file.conversationId}`
                              )
                            }
                          >
                            View conversation
                          </button>
                        ) : (
                          <span
                            className="text-muted"
                            style={{ fontSize: '0.8em' }}
                            title="tshark --export-objects does not expose which TCP stream each HTTP object came from"
                          >
                            —
                          </span>
                        )}
                      </td>
                      <td>{methodBadge(file.extractionMethod)}</td>
                      <td>
                        {isSkipped ? (
                          <span
                            className="badge bg-warning text-dark"
                            title="File exceeds the 50 MB size limit and was not stored"
                          >
                            <i className="bi bi-slash-circle me-1"></i>
                            Too large
                          </span>
                        ) : (
                          <div className="d-flex gap-1">
                            {nativePreviewMode(file.mimeType) && (
                              <button
                                className="btn btn-outline-secondary btn-sm text-nowrap"
                                onClick={() => setPreviewFile(file)}
                                title="Preview in browser"
                              >
                                <i className="bi bi-play-circle me-1"></i>
                                Preview
                              </button>
                            )}
                            <button
                              className="btn btn-outline-primary btn-sm text-nowrap"
                              onClick={() => handleDownloadRequest(file)}
                            >
                              <i className="bi bi-download me-1"></i>
                              Download
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </ScrollableTable>
          )}
        </div>
      </div>

      {/* Inline media preview modal */}
      <Modal show={previewFile !== null} onHide={() => setPreviewFile(null)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-play-circle me-2"></i>
            Preview — {previewFile?.filename ?? '(unnamed)'}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body className="text-center">
          {previewFile && (() => {
            const mode = nativePreviewMode(previewFile.mimeType);
            const url = getPreviewUrl(fileId, previewFile.id);
            if (mode === 'audio') {
              return (
                <audio controls src={url} style={{ width: '100%' }}>
                  Your browser does not support audio playback.
                </audio>
              );
            }
            if (mode === 'video') {
              return (
                <video controls src={url} style={{ maxWidth: '100%', maxHeight: '60vh' }}>
                  Your browser does not support video playback.
                </video>
              );
            }
            if (mode === 'image') {
              return (
                <img
                  src={url}
                  alt={previewFile.filename ?? 'preview'}
                  style={{ maxWidth: '100%', maxHeight: '60vh', objectFit: 'contain' }}
                />
              );
            }
            return null;
          })()}
          <div className="alert alert-warning mt-3 mb-0 text-start" style={{ fontSize: '0.8rem' }}>
            <i className="bi bi-exclamation-triangle-fill me-1"></i>
            Content rendered from a packet capture. Do not interact with active content on a
            production system.
          </div>
        </Modal.Body>
        <Modal.Footer>
          <button className="btn btn-secondary" onClick={() => setPreviewFile(null)}>
            Close
          </button>
          <button
            className="btn btn-outline-primary"
            onClick={() => { setPreviewFile(null); handleDownloadRequest(previewFile!); }}
          >
            <i className="bi bi-download me-1"></i>
            Download
          </button>
        </Modal.Footer>
      </Modal>

      {/* Safety disclaimer modal */}
      <Modal show={pendingDownload !== null} onHide={() => setPendingDownload(null)}>
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="bi bi-exclamation-triangle-fill text-warning me-2"></i>
            Download Warning
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>You are about to download a file that was extracted from a packet capture:</p>
          <div className="alert alert-secondary font-monospace" style={{ fontSize: '0.85em' }}>
            {pendingDownload?.filename ?? '(unnamed)'}{' '}
            {pendingDownload?.fileSize != null && (
              <span className="text-muted">({formatBytes(pendingDownload.fileSize)})</span>
            )}
          </div>
          <div className="alert alert-warning mb-0">
            <strong>Safety disclaimer:</strong> This file was transferred over the network and may
            contain malware, scripts, or other active content. Do <strong>not</strong> open or
            execute it on a production system. Use an isolated, sandboxed environment for analysis.
          </div>
        </Modal.Body>
        <Modal.Footer>
          <button className="btn btn-secondary" onClick={() => setPendingDownload(null)}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={confirmDownload}>
            <i className="bi bi-download me-1"></i>
            Download anyway
          </button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};
