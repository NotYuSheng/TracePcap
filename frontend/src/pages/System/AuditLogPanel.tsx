import { useEffect, useMemo, useRef, useState } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { Spinner } from '@components/common/Spinner/Spinner';
import { meService, type AuditLogEntry, type Paged } from '@/features/me/meService';
import { AUDIT_KINDS, describeAction, diffValues, kindOf, summarize } from '@/features/me/auditDiff';
import { useEscapeLayer } from '@utils/useEscapeLayer';
import './AuditLogPanel.css';

const PAGE_SIZE = 25;
const SEARCH_DELAY_MS = 300;

function when(at: string): string {
  const d = new Date(at);
  const today = new Date();
  const time = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  if (d.toDateString() === today.toDateString()) return `Today ${time}`;
  return `${d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} ${time}`;
}

/** The details of one entry: what changed field by field, who, when, what it was about. */
function Details({ entry, onClose }: { entry: AuditLogEntry; onClose: () => void }) {
  const ref = useRef<HTMLElement>(null);
  const [raw, setRaw] = useState(false);
  useEscapeLayer(onClose, { ref });
  const changes = diffValues(entry.before, entry.after);
  const whole = entry.before == null ? 'Added' : entry.after == null ? 'Removed' : null;
  return (
    <aside ref={ref} className="audit-details" aria-labelledby="audit-details-title">
      <div className="audit-details-head">
        <div>
          <div className="audit-details-kind">{describeAction(entry.action)}</div>
          <h3 id="audit-details-title" className="audit-details-title">
            {summarize(entry)}
          </h3>
        </div>
        <button type="button" className="audit-details-close" onClick={onClose} aria-label="Close the details">
          <i className="bi bi-x-lg" aria-hidden="true" />
        </button>
      </div>
      <dl className="audit-details-facts">
        <dt>When</dt>
        <dd>{new Date(entry.at).toLocaleString()}</dd>
        <dt>Who</dt>
        <dd>{entry.actor}</dd>
        <dt>About</dt>
        <dd>
          {entry.targetType}
          {entry.targetId && (
            <>
              {' · '}
              <span className="font-monospace audit-target">{entry.targetId}</span>
            </>
          )}
        </dd>
      </dl>
      <div className="audit-details-section">
        {whole ?? 'What changed'}
      </div>
      {changes.length === 0 ? (
        <p className="text-muted small mb-0">No field changed.</p>
      ) : (
        <div className="audit-details-changes">
          {changes.map(c => (
            <div key={c.field} className="audit-change-card">
              <div className="audit-change-field">{c.field}</div>
              {c.kind === 'changed' ? (
                <div className="audit-change-values">
                  <span className="audit-change-label">Before</span>
                  <span className="audit-old-text">{c.before}</span>
                  <span className="audit-change-label">After</span>
                  <span className="audit-new-text">{c.after}</span>
                </div>
              ) : (
                <div className="audit-change-values">
                  <span className="audit-change-label">{c.kind === 'added' ? (whole ? 'Value' : 'Added') : whole ? 'Value' : 'Removed'}</span>
                  <span className={c.kind === 'added' && !whole ? 'audit-new-text' : c.kind === 'removed' && !whole ? 'audit-old-text' : ''}>
                    {c.after ?? c.before}
                  </span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <Button variant="outline-secondary" size="sm" className="align-self-start" onClick={() => setRaw(r => !r)} aria-expanded={raw}>
        {raw ? 'Hide the raw record' : 'Show the raw record'}
      </Button>
      {raw && <pre className="audit-raw">{JSON.stringify({ action: entry.action, before: entry.before, after: entry.after }, null, 2)}</pre>}
    </aside>
  );
}

/** Who changed what, when (#915). Newest first, searchable, filterable by kind; a row opens its details. */
export function AuditLogPanel() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<string | null>(null);
  const [result, setResult] = useState<Paged<AuditLogEntry> | null>(null);
  const [error, setError] = useState(false);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(search.trim());
      setPage(1);
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(t);
  }, [search]);

  const types = useMemo(() => AUDIT_KINDS.find(k => k.key === kind)?.types, [kind]);

  useEffect(() => {
    let active = true;
    meService
      .getAuditLog(page, PAGE_SIZE, query || undefined, types)
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
  }, [page, query, types]);

  const entry = result?.data.find(e => e.id === selected) ?? null;
  const pick = (k: string | null) => {
    setKind(k);
    setPage(1);
    setSelected(null);
  };

  return (
    <div>
      <p className="small text-muted">
        Every change to settings, rules, maps and permissions, with who made it. With login off the
        actor is <span className="font-monospace">system</span>, because there are no accounts.
        Select a row for the details.
      </p>
      <div className="audit-toolbar">
        <Form.Control
          type="search"
          size="sm"
          placeholder="Search by who, action or target…"
          aria-label="Search the audit log"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="audit-chips" role="group" aria-label="Show">
          {[{ key: null as string | null, label: 'All' }, ...AUDIT_KINDS.map(k => ({ key: k.key as string | null, label: k.label }))].map(c => (
            <button
              key={c.label}
              type="button"
              className={`audit-chip${kind === c.key ? ' audit-chip-on' : ''}`}
              aria-pressed={kind === c.key}
              onClick={() => pick(c.key)}
            >
              {c.label}
            </button>
          ))}
        </div>
      </div>
      {error && <p className="text-danger small">Couldn't load the audit log.</p>}
      {!error && !result && (
        <div className="text-muted small py-3">
          <Spinner animation="border" size="sm" className="me-2" />
          Loading…
        </div>
      )}
      {result && result.total === 0 && (
        <p className="small text-muted">
          {query || kind ? 'No entries match.' : 'No changes recorded yet.'}
        </p>
      )}
      {result && result.total > 0 && (
        <div className={`audit-layout${entry ? ' audit-layout-open' : ''}`}>
          <div className="audit-table-wrap">
            <table className="table table-sm small align-middle audit-table mb-0">
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Who</th>
                  <th scope="col">Change</th>
                </tr>
              </thead>
              <tbody>
                {result.data.map(e => (
                  <tr
                    key={e.id}
                    className={e.id === selected ? 'audit-row-on' : undefined}
                    aria-selected={e.id === selected}
                  >
                    <td className="text-nowrap text-muted">{when(e.at)}</td>
                    <td>{e.actor}</td>
                    <td>
                      <button type="button" className="audit-row-button" onClick={() => setSelected(s => (s === e.id ? null : e.id))}>
                        <span className={`audit-kind audit-kind-${kindOf(e.targetType).toLowerCase()}`}>{kindOf(e.targetType)}</span>
                        {summarize(e)}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {result.totalPages > 1 && (
              <Pagination
                currentPage={page}
                totalPages={result.totalPages}
                totalItems={result.total}
                pageSize={PAGE_SIZE}
                onPageChange={p => {
                  setPage(p);
                  setSelected(null);
                }}
                showPageSizeSelector={false}
              />
            )}
          </div>
          {entry && <Details entry={entry} onClose={() => setSelected(null)} />}
        </div>
      )}
    </div>
  );
}
