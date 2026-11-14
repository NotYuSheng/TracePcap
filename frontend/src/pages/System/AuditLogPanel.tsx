import { useEffect, useState } from 'react';
import { Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { Spinner } from '@components/common/Spinner/Spinner';
import { meService, type AuditLogEntry, type Paged } from '@/features/me/meService';
import { describeAction, diffValues } from '@/features/me/auditDiff';
import './AuditLogPanel.css';

const PAGE_SIZE = 25;
const SEARCH_DELAY_MS = 300;

/** Rows shown before "Show N more". */
const SHOWN = 4;

/** What an entry changed: only the fields that differ, as before → after; every field when added or removed. */
function Changes({ before, after }: { before?: Record<string, unknown> | null; after?: Record<string, unknown> | null }) {
  const [open, setOpen] = useState(false);
  const changes = diffValues(before, after);
  if (changes.length === 0) return <span className="text-muted">No field changed</span>;
  const shown = open ? changes : changes.slice(0, SHOWN);
  const whole = before == null ? 'Added' : after == null ? 'Removed' : null;
  return (
    <div className="audit-changes">
      {whole && <span className={`audit-tag audit-tag-${whole === 'Added' ? 'added' : 'removed'}`}>{whole}</span>}
      <dl className="audit-fields">
        {shown.map(c => (
          <div key={c.field} className="audit-field">
            <dt>{c.field}</dt>
            <dd>
              {c.kind === 'changed' && (
                <>
                  <del className="audit-old">{c.before}</del>
                  <i className="bi bi-arrow-right mx-1 text-muted" aria-label="changed to" />
                  <ins className="audit-new">{c.after}</ins>
                </>
              )}
              {c.kind === 'added' && (whole ? <span>{c.after}</span> : <ins className="audit-new">{c.after}</ins>)}
              {c.kind === 'removed' && (whole ? <span>{c.before}</span> : <del className="audit-old">{c.before}</del>)}
            </dd>
          </div>
        ))}
      </dl>
      {changes.length > SHOWN && (
        <button type="button" className="btn btn-link btn-sm p-0" onClick={() => setOpen(o => !o)} aria-expanded={open}>
          {open ? 'Show fewer' : `Show ${changes.length - SHOWN} more`}
        </button>
      )}
    </div>
  );
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
        <p className="small text-muted">
          {query ? `No entries match "${query}".` : 'No changes recorded yet.'}
        </p>
      )}
      {result && result.total > 0 && (
        <>
          <div className="table-responsive">
            <table className="table table-sm small align-middle">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Who</th>
                  <th scope="col" className="audit-what">What</th>
                  <th scope="col" className="audit-change">Change</th>
                </tr>
              </thead>
              <tbody>
                {result.data.map(e => (
                  <tr key={e.id}>
                    <td className="text-nowrap">{new Date(e.at).toLocaleString()}</td>
                    <td>{e.actor}</td>
                    <td>
                      <div className="fw-semibold">{describeAction(e.action)}</div>
                      <div className="text-muted font-monospace audit-code">{e.action}</div>
                      <div className="text-muted">
                        {e.targetType}
                        {e.targetId && (
                          <>
                            {' '}
                            · <span className="font-monospace audit-target">{e.targetId}</span>
                          </>
                        )}
                      </div>
                    </td>
                    <td>
                      <Changes before={e.before} after={e.after} />
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
