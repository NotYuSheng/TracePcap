import { useState, useEffect, useCallback, useMemo } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import type { AnalysisData } from '@/types';
import {
  getExtractedFiles,
  getExtractionWarnings,
  getDownloadUrl,
  getPreviewUrl,
  type ExtractedFile,
  type ExtractionWarnings,
} from '@features/extractedFiles/services/extractedFilesService';
import { LoadingSpinner } from '@components/common/LoadingSpinner';
import { ErrorMessage } from '@components/common/ErrorMessage';
import { ScrollableTable } from '@components/common/ScrollableTable';
import { PillSectionHeader } from '@components/common/PillSectionHeader/PillSectionHeader';
import { Badge, Button, Card, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { formatBytes } from '@/utils/formatters';
import '@components/conversation/ConversationFilterPanel/ConversationFilterPanel.css';

interface AnalysisOutletContext {
  data: AnalysisData;
  fileId: string;
}

type SortField = 'filename' | 'mimeType' | 'fileSize' | 'extractionMethod';
type SortDir = 'asc' | 'desc';

const ExtractionInfoCard = ({ maxFileSizeMb }: { maxFileSizeMb: number }) => {
  const [collapsed, setCollapsed] = useState(true);
  return (
    <Card className="mb-3" style={{ overflow: 'hidden' }}>
      <Card.Header
        className="d-flex align-items-center justify-content-between"
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
      </Card.Header>
      {!collapsed && (
        <Card.Body className="small text-muted">
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
            larger than {maxFileSizeMb} MB are not stored; they appear in this list with a{' '}
            <Badge bg="warning" text="dark" style={{ fontSize: '0.85em' }}>Too large</Badge>{' '}
            badge so you can see they were detected but skipped.
          </p>
        </Card.Body>
      )}
    </Card>
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

/** Renders a capped, comma-separated list of conversation links (by short id) for a warning. */
const ConvLinks = ({
  ids,
  fileId,
  navigate,
}: {
  ids: string[];
  fileId: string;
  navigate: ReturnType<typeof useNavigate>;
}) => {
  const MAX = 10;
  const shown = ids.slice(0, MAX);
  return (
    <>
      {shown.map((cid, i) => (
        <span key={cid}>
          <Button
            variant="link"
            size="sm"
            className="p-0 align-baseline font-monospace"
            style={{ fontSize: 'inherit' }}
            onClick={() => navigate(`/analysis/${fileId}/conversations?highlight=${cid}`)}
          >
            {cid.slice(0, 8)}
          </Button>
          {i < shown.length - 1 ? ', ' : ''}
        </span>
      ))}
      {ids.length > MAX && <span> and {ids.length - MAX} more</span>}
    </>
  );
};

function methodBadge(method: string | null) {
  if (method === 'tshark_http') return <Badge bg="primary">HTTP</Badge>;
  if (method === 'magic_bytes') return <Badge bg="secondary">Raw stream</Badge>;
  return <Badge bg="light" text="dark">{method ?? '—'}</Badge>;
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
      <Button
        variant="link"
        size="sm"
        className="p-0 text-muted"
        style={{ fontSize: '0.75em', lineHeight: 1 }}
        onClick={copy}
        title={copied ? 'Copied!' : 'Copy full hash'}
      >
        <i className={`bi ${copied ? 'bi-check text-success' : 'bi-clipboard'}`}></i>
      </Button>
    </span>
  );
};

export const ExtractedFilesPage = () => {
  const { fileId } = useOutletContext<AnalysisOutletContext>();
  const navigate = useNavigate();
  const [files, setFiles] = useState<ExtractedFile[]>([]);
  const [warnings, setWarnings] = useState<ExtractionWarnings | null>(null);
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
    // Warnings are non-critical — failure here should not block the file list.
    getExtractionWarnings(fileId)
      .then(setWarnings)
      .catch(() => setWarnings(null));
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
        <Badge bg="secondary" className="fs-6">
          {mimeTypeFilter.length > 0
            ? `${sorted.length} / ${files.length}`
            : files.length}{' '}
          file{files.length !== 1 ? 's' : ''}
        </Badge>
      </div>

      {warnings &&
        (warnings.matchLimitConversationIds.length > 0 ||
          warnings.conversationLimitSkippedCount > 0 ||
          warnings.sizeLimitFiles.length > 0) && (
          <Alert variant="warning" className="mb-3">
            <Alert.Heading className="h6 mb-2">
              <i className="bi bi-exclamation-triangle-fill me-2"></i>
              Extraction may be incomplete
            </Alert.Heading>
            <p className="mb-2 small">
              One or more extraction limits were reached for this capture, so some files may be
              missing from the list below. Raise the relevant environment variable and re-run the
              analysis to extract more. Conversation links are shown by short stream id.
            </p>
            <ul className="mb-0 small">
              {warnings.matchLimitConversationIds.length > 0 && (
                <li>
                  <strong>{warnings.matchLimitConversationIds.length}</strong> raw stream(s) hit the
                  per-stream cap of <strong>{warnings.maxMatchesPerStream}</strong> file(s) —
                  additional embedded files may exist. Raise{' '}
                  <code>EXTRACTION_MAX_MATCHES_PER_STREAM</code>. Affected:{' '}
                  <ConvLinks
                    ids={warnings.matchLimitConversationIds}
                    fileId={fileId}
                    navigate={navigate}
                  />
                  .
                </li>
              )}
              {warnings.conversationLimitSkippedCount > 0 && (
                <li>
                  <strong>{warnings.conversationLimitSkippedCount}</strong> non-HTTP stream(s) with
                  detected files were not scanned (only the first{' '}
                  <strong>{warnings.maxStreamConversations}</strong> are). Raise{' '}
                  <code>EXTRACTION_MAX_STREAM_CONVERSATIONS</code>.
                  {warnings.conversationLimitSkippedIds.length > 0 && (
                    <>
                      {' '}
                      Skipped:{' '}
                      <ConvLinks
                        ids={warnings.conversationLimitSkippedIds}
                        fileId={fileId}
                        navigate={navigate}
                      />
                      .
                    </>
                  )}
                </li>
              )}
              {warnings.sizeLimitFiles.length > 0 && (
                <li>
                  <strong>{warnings.sizeLimitFiles.length}</strong> file(s) exceeded the{' '}
                  <strong>{warnings.maxFileSizeMb} MB</strong> per-file limit and were not stored
                  (shown with a “Too large” badge below). Raise{' '}
                  <code>EXTRACTION_MAX_FILE_SIZE_MB</code>.
                  <ul className="mb-0">
                    {warnings.sizeLimitFiles.slice(0, 10).map(f => (
                      <li key={f.id}>
                        <span className="font-monospace">{f.filename ?? '(unnamed)'}</span>
                        {f.fileSize != null && <> ({formatBytes(f.fileSize)})</>}
                        {f.conversationId && (
                          <>
                            {' '}
                            —{' '}
                            <Button
                              variant="link"
                              size="sm"
                              className="p-0 align-baseline"
                              style={{ fontSize: 'inherit' }}
                              onClick={() =>
                                navigate(
                                  `/analysis/${fileId}/conversations?highlight=${f.conversationId}`
                                )
                              }
                            >
                              view conversation
                            </Button>
                          </>
                        )}
                      </li>
                    ))}
                    {warnings.sizeLimitFiles.length > 10 && (
                      <li>and {warnings.sizeLimitFiles.length - 10} more</li>
                    )}
                  </ul>
                </li>
              )}
            </ul>
          </Alert>
        )}

      <ExtractionInfoCard maxFileSizeMb={warnings?.maxFileSizeMb ?? 50} />

      {/* Filter panel */}
      {allMimeTypes.length > 0 && (
        <div className="conversation-filter-panel mb-3">
          <div className="d-flex align-items-center gap-2">
            <Button
              type="button"
              variant="outline-secondary"
              size="sm"
              onClick={() => setFilterOpen(o => !o)}
            >
              <i className="bi bi-funnel me-1"></i>
              Filters
              {mimeTypeFilter.length > 0 && (
                <Badge bg="primary" className="ms-2">{mimeTypeFilter.length}</Badge>
              )}
              <i className={`bi ms-2 ${filterOpen ? 'bi-chevron-up' : 'bi-chevron-down'}`}></i>
            </Button>
          </div>
          {filterOpen && (
            <Card className="mt-2 filter-panel-body">
              <Card.Body className="p-3">
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
                    <Button
                      type="button"
                      size="sm"
                      variant="outline-secondary"
                      onClick={() => setMimeTypeFilter([])}
                    >
                      <i className="bi bi-x-circle me-1"></i>Clear filters
                    </Button>
                  </div>
                )}
              </Card.Body>
            </Card>
          )}
        </div>
      )}

      <Card>
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h6 className="mb-0">Files</h6>
          <small className="text-muted">Click a column header to sort</small>
        </Card.Header>
        <Card.Body className="p-0" style={{ position: 'relative' }}>
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
                          <Button
                            variant="link"
                            size="sm"
                            className="p-0"
                            style={{ fontSize: '0.8em' }}
                            onClick={() =>
                              navigate(
                                `/analysis/${fileId}/conversations?highlight=${file.conversationId}`
                              )
                            }
                          >
                            View conversation
                          </Button>
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
                          <Badge
                            bg="warning"
                            text="dark"
                            title={`File exceeds the ${warnings?.maxFileSizeMb ?? 50} MB size limit and was not stored`}
                          >
                            <i className="bi bi-slash-circle me-1"></i>
                            Too large
                          </Badge>
                        ) : (
                          <div className="d-flex gap-1">
                            {nativePreviewMode(file.mimeType) && (
                              <Button
                                variant="outline-secondary"
                                size="sm"
                                className="text-nowrap"
                                onClick={() => setPreviewFile(file)}
                                title="Preview in browser"
                              >
                                <i className="bi bi-play-circle me-1"></i>
                                Preview
                              </Button>
                            )}
                            <Button
                              variant="outline-primary"
                              size="sm"
                              className="text-nowrap"
                              onClick={() => handleDownloadRequest(file)}
                            >
                              <i className="bi bi-download me-1"></i>
                              Download
                            </Button>
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
        </Card.Body>
      </Card>

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
          <Alert variant="warning" className="mt-3 mb-0 text-start" style={{ fontSize: '0.8rem' }}>
            <i className="bi bi-exclamation-triangle-fill me-1"></i>
            Content rendered from a packet capture. Do not interact with active content on a
            production system.
          </Alert>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setPreviewFile(null)}>
            Close
          </Button>
          <Button
            variant="outline-primary"
            onClick={() => { setPreviewFile(null); handleDownloadRequest(previewFile!); }}
          >
            <i className="bi bi-download me-1"></i>
            Download
          </Button>
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
          <Alert variant="secondary" className="font-monospace" style={{ fontSize: '0.85em' }}>
            {pendingDownload?.filename ?? '(unnamed)'}{' '}
            {pendingDownload?.fileSize != null && (
              <span className="text-muted">({formatBytes(pendingDownload.fileSize)})</span>
            )}
          </Alert>
          <Alert variant="warning" className="mb-0">
            <strong>Safety disclaimer:</strong> This file was transferred over the network and may
            contain malware, scripts, or other active content. Do <strong>not</strong> open or
            execute it on a production system. Use an isolated, sandboxed environment for analysis.
          </Alert>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setPendingDownload(null)}>
            Cancel
          </Button>
          <Button variant="primary" onClick={confirmDownload}>
            <i className="bi bi-download me-1"></i>
            Download anyway
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
};
