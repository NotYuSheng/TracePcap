import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { isAxiosError } from 'axios';
import { Button, Dropdown, Form, Modal } from '@govtechsg/sgds-react';
import { Alert } from '@components/common/Alert';
import { Spinner } from '@components/common/Spinner/Spinner';
import { Pagination } from '@components/common/Pagination/Pagination';
import { apiClient } from '@/services/api/client';
import { API_ENDPOINTS } from '@/services/api/endpoints';
import { parseDateTime } from '@/utils/dateUtils';
import { formatBytes } from '@/utils/formatters';
import { actionOf, EXPIRING_WITHIN_MS, expiresAt, notesOf, statusOf } from './fileStatus';
import './FileList.css';

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

type Membership = { networkId: string; networkName: string };
export type CaptureFilter = 'all' | 'expiring' | 'kept' | 'failed';

const SEARCH_DELAY_MS = 300;

/** "2 hours", "40 minutes": how long until a capture is deleted. */
function expiresIn(ms: number): string {
  const mins = Math.max(1, Math.round(ms / 60000));
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'}`;
  const hours = Math.round(mins / 60);
  return `${hours} hour${hours === 1 ? '' : 's'}`;
}

function ago(ms: number, now: number): string {
  const mins = Math.max(0, Math.floor((now - ms) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(ms).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}

/**
 * The query for a chip: the files endpoint's filters, built from what the page knows (which
 * captures are kept with a network, how long captures are kept).
 */
export function filterParams(
  filter: CaptureFilter,
  ctx: { keptIds: string[]; retentionHours: number | null; now: number }
): Record<string, unknown> | null {
  switch (filter) {
    case 'all':
      return {};
    case 'kept':
      return {
        fileIds: ctx.keptIds.length ? ctx.keptIds : ['00000000-0000-0000-0000-000000000000'],
      };
    case 'failed':
      return { status: ['FAILED'] };
    case 'expiring':
      if (!ctx.retentionHours) return null;
      return {
        source: 'ANALYSIS',
        status: ['COMPLETED'],
        excludeFileIds: ctx.keptIds,
        uploadedBefore: ctx.now - ctx.retentionHours * 3600_000 + EXPIRING_WITHIN_MS,
      };
  }
}

const FILTER_LABELS: Record<CaptureFilter, string> = {
  all: 'All',
  expiring: 'Expiring soon',
  kept: 'Kept with a network',
  failed: 'Failed',
};

interface FileListProps {
  /** Rows per page to start with; the home page shows a short list. */
  defaultPageSize?: number;
}

/**
 * Your captures (All uploads A, in the home page): search, status chips, one row per capture
 * with its status and notes, and a selection bar for Compare, Merge and Delete.
 */
export const FileList = ({ defaultPageSize = 25 }: FileListProps = {}) => {
  const navigate = useNavigate();
  const [files, setFiles] = useState<FileMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(defaultPageSize);
  const [totalItems, setTotalItems] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<CaptureFilter>('all');
  const [showMonitor, setShowMonitor] = useState(false);
  const [counts, setCounts] = useState<Partial<Record<CaptureFilter, number>>>({});

  // What the statuses need beyond the page itself. Each is optional: without it the list shows less.
  const [retentionHours, setRetentionHours] = useState<number | null>(null);
  const [memberships, setMemberships] = useState<Map<string, Membership[]>>(new Map());
  const [staleIds, setStaleIds] = useState<Set<string>>(new Set());
  const [now, setNow] = useState(() => Date.now());

  // Selection survives paging: remember each picked capture's name for the merge name.
  const [selected, setSelected] = useState<Map<string, string>>(new Map());
  const [pendingDelete, setPendingDelete] = useState<FileMetadata[] | null>(null);
  const [showMerge, setShowMerge] = useState(false);
  const [mergeName, setMergeName] = useState('');
  const [merging, setMerging] = useState(false);
  const [mergeError, setMergeError] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(search.trim());
      setPage(1);
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    apiClient
      .get<{ fileRetentionHours?: number }>(API_ENDPOINTS.SYSTEM_LIMITS)
      .then(r => setRetentionHours(r.data.fileRetentionHours ?? null))
      .catch(() => {});
    apiClient
      .get<(Membership & { fileId: string })[]>(API_ENDPOINTS.NETWORK_MEMBERSHIPS)
      .then(r => {
        const m = new Map<string, Membership[]>();
        for (const x of r.data) m.set(x.fileId, [...(m.get(x.fileId) ?? []), x]);
        setMemberships(m);
      })
      .catch(() => {});
    apiClient
      .get<string[]>(API_ENDPOINTS.STALE_CAPTURES)
      .then(r => setStaleIds(new Set(r.data)))
      .catch(() => {});
  }, []);

  const keptIds = useMemo(() => [...memberships.keys()], [memberships]);

  // The shared part of every query: name search and the monitor-uploads toggle.
  const baseParams = useCallback(
    (f: CaptureFilter): Record<string, unknown> | null => {
      const p = filterParams(f, { keptIds, retentionHours, now: Date.now() });
      if (p == null) return null;
      return {
        ...(showMonitor || f === 'kept' || 'source' in p ? {} : { source: 'ANALYSIS' }),
        ...(query ? { search: query } : {}),
        ...p,
      };
    },
    [keptIds, retentionHours, query, showMonitor]
  );

  const fetchFiles = useCallback(async () => {
    const params = baseParams(filter);
    if (params == null) {
      setFiles([]);
      setTotalItems(0);
      setTotalPages(0);
      setLoading(false);
      return;
    }
    try {
      const res = await apiClient.get(API_ENDPOINTS.FILES_LIST, {
        params: { sort: 'uploadedAt,desc', page, pageSize, ...params },
        paramsSerializer: { indexes: null },
      });
      setFiles(res.data.data ?? []);
      setTotalItems(res.data.total ?? 0);
      setTotalPages(res.data.totalPages ?? 0);
      setNow(Date.now());
    } catch (err) {
      console.error('Failed to fetch files:', err);
    } finally {
      setLoading(false);
    }
  }, [baseParams, filter, page, pageSize]);

  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  // How many each chip would show, with the same search and toggle.
  useEffect(() => {
    let alive = true;
    const keys: CaptureFilter[] = ['all', 'expiring', 'kept', 'failed'];
    Promise.all(
      keys.map(async k => {
        const params = baseParams(k);
        if (params == null) return [k, 0] as const;
        try {
          const res = await apiClient.get(API_ENDPOINTS.FILES_LIST, {
            params: { page: 1, pageSize: 1, ...params },
            paramsSerializer: { indexes: null },
          });
          return [k, res.data.total ?? 0] as const;
        } catch {
          return [k, undefined] as const;
        }
      })
    ).then(rows => {
      if (alive) setCounts(Object.fromEntries(rows.filter(([, n]) => n != null)));
    });
    return () => {
      alive = false;
    };
  }, [baseParams, files]);

  const toggle = (f: FileMetadata) =>
    setSelected(prev => {
      const next = new Map(prev);
      if (next.has(f.fileId)) next.delete(f.fileId);
      else next.set(f.fileId, f.fileName);
      return next;
    });
  const pageIds = files.map(f => f.fileId);
  const allOnPage = pageIds.length > 0 && pageIds.every(id => selected.has(id));
  const toggleAllOnPage = () =>
    setSelected(prev => {
      const next = new Map(prev);
      if (allOnPage) pageIds.forEach(id => next.delete(id));
      else files.forEach(f => next.set(f.fileId, f.fileName));
      return next;
    });

  const autoMergeName = () => {
    const names = [...selected.values()];
    const parts = names.slice(0, 3).map(n => n.replace(/\.[^.]+$/, '').slice(0, 20));
    return `merged_${parts.join('+')}${names.length > 3 ? `+${names.length - 3}_more` : ''}`;
  };

  const doMerge = async () => {
    setMergeError(null);
    setMerging(true);
    try {
      const name = mergeName.trim() || autoMergeName();
      const res = await apiClient.post(API_ENDPOINTS.FILES_MERGE, {
        fileIds: [...selected.keys()],
        mergedFileName: name.endsWith('.pcap') ? name : `${name}.pcap`,
      });
      setSelected(new Map());
      setShowMerge(false);
      navigate(`/analysis/${res.data.fileId}`);
    } catch (err) {
      setMergeError(
        isAxiosError(err) && err.response?.data?.message
          ? err.response.data.message
          : 'Couldn’t merge the captures. Try again.'
      );
    } finally {
      setMerging(false);
    }
  };

  const doDelete = async () => {
    if (!pendingDelete) return;
    await Promise.allSettled(
      pendingDelete.map(f => apiClient.delete(API_ENDPOINTS.FILE_DELETE(f.fileId)))
    );
    setSelected(prev => {
      const next = new Map(prev);
      pendingDelete.forEach(f => next.delete(f.fileId));
      return next;
    });
    setPendingDelete(null);
    if (pendingDelete.length >= files.length && page === totalPages && page > 1)
      setPage(p => p - 1);
    else fetchFiles();
  };

  const selectedCount = selected.size;

  return (
    <section className="captures-card" aria-labelledby="captures-title">
      <div className="captures-head">
        <h2 id="captures-title" className="captures-title">
          Your captures
        </h2>
        {counts.all != null && <span className="captures-count">{counts.all}</span>}
        <Form.Control
          type="search"
          size="sm"
          className="captures-search"
          placeholder="Search by name"
          aria-label="Search captures"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>
      <div className="captures-filters">
        <div role="group" aria-label="Show" className="d-flex flex-wrap gap-2">
          {(Object.keys(FILTER_LABELS) as CaptureFilter[]).map(k => (
            <button
              key={k}
              type="button"
              className={`captures-chip${filter === k ? ' active' : ''}`}
              aria-pressed={filter === k}
              onClick={() => {
                setFilter(k);
                setPage(1);
              }}
            >
              {FILTER_LABELS[k]}
              {counts[k] != null && ` ${counts[k]}`}
            </button>
          ))}
        </div>
        <Form.Check
          type="checkbox"
          id="captures-show-monitor"
          className="captures-monitor"
          label="Show monitor uploads"
          checked={showMonitor}
          onChange={e => {
            setShowMonitor(e.target.checked);
            setPage(1);
          }}
        />
      </div>

      {loading ? (
        <div className="text-center text-muted py-4">
          <Spinner animation="border" size="sm" className="me-2" />
          Loading captures…
        </div>
      ) : files.length === 0 ? (
        <p className="text-center text-muted py-4 mb-0">
          {query || filter !== 'all'
            ? 'No captures match.'
            : 'No captures yet. Drop one in the panel to start.'}
        </p>
      ) : (
        <div className="table-responsive">
          <table className="table align-middle mb-0 captures-table">
            <thead>
              <tr>
                <th scope="col" className="captures-check">
                  <Form.Check
                    type="checkbox"
                    aria-label="Select all on this page"
                    checked={allOnPage}
                    onChange={toggleAllOnPage}
                  />
                </th>
                <th scope="col">Capture</th>
                <th scope="col" className="captures-status-col">
                  Status
                </th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {files.map(file => {
                const uploaded = parseDateTime(file.uploadedAt);
                const ctx = {
                  retentionHours,
                  keptWith: memberships.get(file.fileId) ?? [],
                  rulesChanged: staleIds.has(file.fileId),
                  now,
                };
                const sf = { ...file, uploadedAt: uploaded };
                const status = statusOf(sf, ctx);
                const notes = notesOf(sf, ctx);
                const expiry = expiresAt(sf, ctx);
                const isSel = selected.has(file.fileId);
                return (
                  <tr key={file.fileId} className={isSel ? 'captures-row-selected' : undefined}>
                    <td className="captures-check">
                      <Form.Check
                        type="checkbox"
                        aria-label={`Select ${file.fileName}`}
                        checked={isSel}
                        onChange={() => toggle(file)}
                      />
                    </td>
                    <td>
                      <Link to={`/analysis/${file.fileId}`} className="captures-name">
                        {file.fileName}
                      </Link>
                      <span
                        className={`captures-status-inline file-status file-status-${status.key}`}
                      >
                        <span className="file-status-dot" aria-hidden="true" />
                        {status.label}
                      </span>
                      <div className="captures-meta">
                        {formatBytes(file.fileSize)}
                        {file.packetCount != null && (
                          <> · {file.packetCount.toLocaleString()} packets</>
                        )}
                        {' · '}
                        {ago(uploaded, now)}
                      </div>
                      {notes.length > 0 && (
                        <div className="file-notes">
                          {notes.map(n =>
                            n.to ? (
                              <Link
                                key={n.key}
                                to={n.to}
                                className={`file-note${n.tone ? ` file-note-${n.tone}` : ''}`}
                              >
                                {n.label}
                              </Link>
                            ) : (
                              <span key={n.key} className="file-note">
                                {n.label}
                              </span>
                            )
                          )}
                        </div>
                      )}
                    </td>
                    <td className="captures-status-cell">
                      <span className={`file-status file-status-${status.key}`}>
                        <span className="file-status-dot" aria-hidden="true" />
                        {status.label}
                      </span>
                      {status.key === 'expiring' && expiry != null && (
                        <div className="captures-meta">deleted in {expiresIn(expiry - now)}</div>
                      )}
                    </td>
                    <td className="text-end text-nowrap">
                      {status.key === 'expiring' ? (
                        <Link to="/monitor" className="btn btn-outline-warning btn-sm">
                          Keep it
                        </Link>
                      ) : (
                        <Link
                          to={`/analysis/${file.fileId}`}
                          className="btn btn-outline-secondary btn-sm captures-open"
                        >
                          {actionOf(status.key)}
                        </Link>
                      )}
                      <Dropdown align="end" className="d-inline-block ms-2">
                        <Dropdown.Toggle
                          variant="outline-secondary"
                          size="sm"
                          className="captures-more"
                          id={`capture-more-${file.fileId}`}
                          aria-label={`More for ${file.fileName}`}
                        >
                          <i className="bi bi-three-dots" aria-hidden="true"></i>
                        </Dropdown.Toggle>
                        <Dropdown.Menu>
                          <Dropdown.Item as={Link} to={`/analysis/${file.fileId}`}>
                            Open
                          </Dropdown.Item>
                          <Dropdown.Item as={Link} to={`/analysis/${file.fileId}/file`}>
                            Re-analyse…
                          </Dropdown.Item>
                          <Dropdown.Divider />
                          <Dropdown.Item
                            className="text-danger"
                            onClick={() => setPendingDelete([file])}
                          >
                            Delete
                          </Dropdown.Item>
                        </Dropdown.Menu>
                      </Dropdown>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedCount > 0 && (
        <div className="captures-selection" role="region" aria-label="Selected captures">
          <b>{selectedCount} selected</b>
          <Button
            size="sm"
            variant="primary"
            disabled={selectedCount < 2}
            onClick={() => navigate(`/compare?files=${[...selected.keys()].join(',')}`)}
          >
            Compare
          </Button>
          <Button
            size="sm"
            variant="outline-light"
            disabled={selectedCount < 2}
            onClick={() => {
              setMergeName(autoMergeName());
              setShowMerge(true);
            }}
          >
            Merge into one
          </Button>
          <Button
            size="sm"
            variant="outline-danger"
            className="captures-delete-selected"
            onClick={() =>
              setPendingDelete(
                [...selected.entries()].map(
                  ([fileId, fileName]) => ({ fileId, fileName }) as FileMetadata
                )
              )
            }
          >
            Delete {selectedCount}
          </Button>
          {selectedCount < 2 && (
            <span className="small opacity-75">Pick two or more to compare or merge.</span>
          )}
          <button type="button" className="captures-clear" onClick={() => setSelected(new Map())}>
            Clear
          </button>
        </div>
      )}

      {totalItems > pageSize && (
        <div className="captures-foot">
          <Pagination
            currentPage={page}
            totalPages={totalPages}
            totalItems={totalItems}
            pageSize={pageSize}
            pageSizeOptions={[...new Set([defaultPageSize, 10, 25, 50, 100])].sort((a, b) => a - b)}
            onPageChange={setPage}
            onPageSizeChange={size => {
              setPageSize(size);
              setPage(1);
            }}
          />
        </div>
      )}

      <Modal show={!!pendingDelete} onHide={() => setPendingDelete(null)} centered>
        <Modal.Header closeButton>
          <Modal.Title>
            Delete{' '}
            {pendingDelete && pendingDelete.length > 1
              ? `${pendingDelete.length} captures`
              : 'capture'}
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {pendingDelete?.length === 1 ? (
            <p className="mb-0">
              Delete <strong>{pendingDelete[0].fileName}</strong> and its analysis?
            </p>
          ) : (
            <p className="mb-0">
              Delete these {pendingDelete?.length} captures and their analyses? A capture kept with
              a network leaves that network too.
            </p>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button type="button" variant="outline-secondary" onClick={() => setPendingDelete(null)}>
            Cancel
          </Button>
          <Button type="button" variant="danger" onClick={doDelete}>
            Delete
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={showMerge} onHide={() => !merging && setShowMerge(false)} centered>
        <Modal.Header closeButton={!merging}>
          <Modal.Title>Merge {selectedCount} captures into one</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {mergeError && (
            <Alert variant="danger" className="py-2">
              {mergeError}
            </Alert>
          )}
          <p className="small text-muted">
            The packets of all of them go into one new capture, which is then analysed. The
            originals stay as they are. To look at them side by side instead, use Compare.
          </p>
          <Form.Label htmlFor="merge-name">Name</Form.Label>
          <div className="input-group input-group-sm">
            <Form.Control
              id="merge-name"
              value={mergeName}
              onChange={e => setMergeName(e.target.value)}
              disabled={merging}
            />
            <span className="input-group-text">.pcap</span>
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button
            type="button"
            variant="outline-secondary"
            onClick={() => setShowMerge(false)}
            disabled={merging}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={doMerge}
            disabled={merging || !mergeName.trim()}
          >
            {merging && <Spinner animation="border" size="sm" className="me-2" />}
            Merge and analyse
          </Button>
        </Modal.Footer>
      </Modal>
    </section>
  );
};
