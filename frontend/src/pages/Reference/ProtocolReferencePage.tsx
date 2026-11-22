import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Badge, Container, Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { SideDrawer } from '@components/common/SideDrawer';
import { Spinner } from '@components/common/Spinner/Spinner';
import {
  CATEGORY_LABELS,
  DETECTION_LABELS,
  findNdpiProtocol,
  useNdpiProtocols,
  type NdpiProtocol,
} from '@/features/ndpiReference/ndpiReference';
import './ProtocolReferencePage.css';

const PAGE_SIZE = 50;

function matches(p: NdpiProtocol, q: string): boolean {
  if (!q) return true;
  const needle = q.toLowerCase();
  return (
    String(p.id) === needle ||
    p.name.toLowerCase().includes(needle) ||
    p.title.toLowerCase().includes(needle) ||
    p.description.toLowerCase().includes(needle)
  );
}

/**
 * Every protocol nDPI can detect, with what it is and how nDPI recognises it. Search, category and
 * the open protocol live in the URL (?q=, ?category=, ?protocol=), so other pages can link
 * straight to an entry and the back button works.
 */
export function ProtocolReferencePage() {
  const protocols = useNdpiProtocols();
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const category = params.get('category') ?? '';
  const page = Math.max(1, Number(params.get('page') ?? 1) || 1);
  const open = params.get('protocol');

  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setParams(next, { replace: true });
  };

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of protocols ?? []) if (matches(p, q)) c[p.category] = (c[p.category] ?? 0) + 1;
    return c;
  }, [protocols, q]);

  const shown = useMemo(
    () => (protocols ?? []).filter(p => matches(p, q) && (!category || p.category === category)),
    [protocols, q, category]
  );
  const totalPages = Math.max(1, Math.ceil(shown.length / PAGE_SIZE));
  const pageRows = shown.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const selected = protocols && open ? findNdpiProtocol(protocols, open) : undefined;
  const matching = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <Container className="py-4 reference-page">
      <h1 className="reference-title">Protocol reference</h1>
      <p className="text-muted">
        The {protocols ? protocols.length : ''} protocols and applications nDPI can recognise in
        traffic: what each one is, and how nDPI tells it apart.
      </p>

      <Form.Control
        type="search"
        className="mb-3 reference-search"
        placeholder="Search by name, ID or keyword (e.g. email, vpn, 443)…"
        aria-label="Search protocols"
        value={q}
        onChange={e => update({ q: e.target.value || null, page: null })}
      />

      <div className="reference-chips mb-3" role="group" aria-label="Category">
        <button
          type="button"
          className={`reference-chip${category ? '' : ' reference-chip-on'}`}
          aria-pressed={!category}
          onClick={() => update({ category: null, page: null })}
        >
          All <span className="reference-chip-count">{matching}</span>
        </button>
        {Object.entries(CATEGORY_LABELS)
          .filter(([key]) => counts[key])
          .map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`reference-chip${category === key ? ' reference-chip-on' : ''}`}
              aria-pressed={category === key}
              onClick={() => update({ category: category === key ? null : key, page: null })}
            >
              {label} <span className="reference-chip-count">{counts[key]}</span>
            </button>
          ))}
      </div>

      {!protocols ? (
        <div className="text-muted small py-3">
          <Spinner animation="border" size="sm" className="me-2" />
          Loading…
        </div>
      ) : shown.length === 0 ? (
        <p className="text-muted">No protocol matches.</p>
      ) : (
        <>
          <table className="table table-sm align-middle reference-table">
            <thead>
              <tr>
                <th scope="col" className="text-end">ID</th>
                <th scope="col">Protocol</th>
                <th scope="col">Category</th>
                <th scope="col">Detected by</th>
              </tr>
            </thead>
            <tbody>
              {pageRows.map(p => (
                <tr key={p.id}>
                  <td className="text-end text-muted font-monospace small">{p.id}</td>
                  <td>
                    <button
                      type="button"
                      className="reference-row-button"
                      onClick={() => update({ protocol: p.name })}
                    >
                      <span className="fw-semibold">{p.name}</span>
                      <span className="d-block small text-muted">{p.title}</span>
                    </button>
                  </td>
                  <td className="small">{CATEGORY_LABELS[p.category] ?? p.category}</td>
                  <td className="small text-muted">{p.detection.map(d => d.label).join(' · ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {totalPages > 1 && (
            <Pagination
              currentPage={Math.min(page, totalPages)}
              totalPages={totalPages}
              totalItems={shown.length}
              pageSize={PAGE_SIZE}
              onPageChange={p => update({ page: p > 1 ? String(p) : null })}
              showPageSizeSelector={false}
            />
          )}
        </>
      )}

      <SideDrawer
        show={!!selected}
        onHide={() => update({ protocol: null })}
        title={selected?.name ?? ''}
        titleId="protocol-reference-title"
      >
        {selected && <ProtocolDetail protocol={selected} />}
      </SideDrawer>
    </Container>
  );
}

/** One protocol's entry: what it is, how nDPI recognises it, and where to read more. */
export function ProtocolDetail({ protocol }: { protocol: NdpiProtocol }) {
  return (
    <div data-testid="protocol-detail">
      <p className="fw-semibold mb-1">{protocol.title}</p>
      <p className="small text-muted mb-3">
        nDPI ID {protocol.id} · {CATEGORY_LABELS[protocol.category] ?? protocol.category}
      </p>
      <h3 className="reference-detail-heading">What it is</h3>
      <p>{protocol.description}</p>
      {protocol.detection.length > 0 && (
        <>
          <h3 className="reference-detail-heading">How nDPI recognises it</h3>
          <ul className="list-unstyled mb-3">
            {protocol.detection.map(d => (
              <li key={d.type + d.label} className="mb-1">
                <Badge bg="light" text="dark" className="me-2 border">
                  {DETECTION_LABELS[d.type] ?? d.type}
                </Badge>
                {d.label}
              </li>
            ))}
          </ul>
        </>
      )}
      {protocol.note && <p className="small text-muted">{protocol.note}</p>}
      {protocol.references.length > 0 && (
        <>
          <h3 className="reference-detail-heading">References</h3>
          <ul className="mb-0">
            {protocol.references.map(r => (
              <li key={r.url}>
                <a href={r.url} target="_blank" rel="noopener noreferrer">
                  {r.label}
                </a>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
