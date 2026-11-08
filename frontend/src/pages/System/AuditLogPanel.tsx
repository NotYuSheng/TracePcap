import { useEffect, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { Spinner } from '@components/common/Spinner/Spinner';
import { meService, type AuditLogEntry, type Paged } from '@/features/me/meService';

const PAGE_SIZE = 25;
const SEARCH_DELAY_MS = 300;

/** Renders a before/after value compactly: `key: value` pairs, or "none" when it didn't exist. */
function describe(value?: Record<string, unknown> | null): string {
  if (!value) return 'none';
  return Object.entries(value)
    .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
    .join(', ');
}

/** Who changed what, when, before and after (#915). Newest first, searchable. */
export function AuditLogPanel() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<Paged<AuditLogEntry> | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(search.trim());
      setPage(1);
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    let active = true;
    meService
      .getAuditLog(page, PAGE_SIZE, query || undefined)
      .then(r => {
        if (!active) return;
        setResult(r);
        setError(false);
      })
      .catch(() => {
        if (active) setError(true);
      });
    return () => {
      active = false;
    };
  }, [page, query]);

  return (
    <div>
      <p className="small text-muted">
        Every change to settings, rules and permissions, with who made it. With login off the actor
        is <span className="font-monospace">system</span>, because there are no accounts.
      </p>
      <Form.Control
        type="search"
        size="sm"
        className="mb-3"
        placeholder="Search by who, action or target…"
        aria-label="Search the audit log"
        value={search}
        onChange={e => setSearch(e.target.value)}
      />
      {error && <p className="text-danger small">Couldn't load the audit log.</p>}
      {!error && !result && (
        <div className="text-muted small py-3">
          <Spinner animation="border" size="sm" className="me-2" />
          Loading…
        </div>
      )}
      {result && result.total === 0 && (
        <p className="small text-muted">{query ? `No entries match "${query}".` : 'No changes recorded yet.'}</p>
      )}
      {result && result.total > 0 && (
        <>
          <div className="table-responsive">
            <table className="table table-sm small align-middle">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Who</th>
                  <th scope="col">What</th>
                  <th scope="col">Change</th>
                </tr>
              </thead>
              <tbody>
                {result.data.map(e => (
                  <tr key={e.id}>
                    <td className="text-nowrap">{new Date(e.at).toLocaleString()}</td>
                    <td>{e.actor}</td>
                    <td>
                      <div className="font-monospace">{e.action}</div>
                      <div className="text-muted">
                        {e.targetType}
                        {e.targetId && <> · <span className="font-monospace">{e.targetId}</span></>}
                      </div>
                    </td>
                    <td>
                      <div>
                        <span className="text-muted">Before:</span> {describe(e.before)}
                      </div>
                      <div>
                        <span className="text-muted">After:</span> {describe(e.after)}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {result.totalPages > 1 && (
            <Pagination
              currentPage={page}
              totalPages={result.totalPages}
              totalItems={result.total}
              pageSize={PAGE_SIZE}
              onPageChange={setPage}
              showPageSizeSelector={false}
            />
          )}
        </>
      )}
    </div>
  );
}
