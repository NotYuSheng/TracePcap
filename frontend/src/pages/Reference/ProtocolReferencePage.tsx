import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Form } from '@govtechsg/sgds-react';
import { Pagination } from '@components/common/Pagination/Pagination';
import { SideDrawer } from '@components/common/SideDrawer';
import { Spinner } from '@components/common/Spinner/Spinner';
import {
  CATEGORY_LABELS,
  DETECTION_LABELS,
  findNdpiProtocol,
  protocolUsageService,
  usageByProtocol,
  useNdpiProtocols,
  useProtocolUsage,
  type NdpiProtocol,
  type ProtocolCapture,
} from '@/features/ndpiReference/ndpiReference';
import './ProtocolReferencePage.css';

const PAGE_SIZE = 60;
const ALL = 'all';
const SEEN = 'seen';

/** One line under each category's heading: what its protocols are for. */
const CATEGORY_BLURBS: Record<string, string> = {
  network: 'the plumbing: addressing, naming, file sharing, sign-in and the protocols everything else runs on',
  web: 'the web and the services built on it',
  email: 'sending, fetching and syncing email',
  social: 'social networks and their apps',
  streaming: 'video and music streaming',
  cloud: 'cloud platforms and online storage',
  vpn: 'tunnels and VPNs that hide or carry other traffic',
  gaming: 'games and gaming platforms',
  database: 'databases and the clients that query them',
  industrial: 'industrial control and building systems (OT, SCADA)',
  messaging: 'chat and calling apps',
  remote: 'controlling another computer',
  iot: 'smart devices, cameras and sensors',
  crypto: 'cryptocurrency and blockchain networks',
  other: 'everything else, including peer-to-peer and developer tools',
};

function matches(p: NdpiProtocol, q: string): boolean {
  if (!q) return true;
  const needle = q.toLowerCase();
  return (
    String(p.id) === needle ||
    p.name.toLowerCase().includes(needle) ||
    p.title.toLowerCase().includes(needle) ||
    p.description.toLowerCase().includes(needle) ||
    p.detection.some(d => d.label.toLowerCase().includes(needle))
  );
}

/**
 * The protocol reference, as a directory: categories down the side, protocols as cards, each
 * entry in the right-hand drawer with where you've seen it. Category, search and the open entry
 * live in the URL (?category=, ?q=, ?protocol=), so links go straight to one.
 */
export function ProtocolReferencePage() {
  const protocols = useNdpiProtocols();
  const usage = useProtocolUsage();
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const category = params.get('category') ?? ALL;
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

  const seen = useMemo(
    () => (protocols && usage ? usageByProtocol(protocols, usage) : new Map()),
    [protocols, usage]
  );

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of protocols ?? []) c[p.category] = (c[p.category] ?? 0) + 1;
    return c;
  }, [protocols]);

  // A search looks across every protocol, whatever category is picked.
  const shown = useMemo(() => {
    const list = (protocols ?? []).filter(p =>
      q
        ? matches(p, q)
        : category === ALL || (category === SEEN ? seen.has(p.name) : p.category === category)
    );
    // Within "seen", the ones in the most captures first.
    if (!q && category === SEEN) {
      list.sort((a, b) => (seen.get(b.name)?.captures ?? 0) - (seen.get(a.name)?.captures ?? 0));
    }
    return list;
  }, [protocols, q, category, seen]);

  const totalPages = Math.max(1, Math.ceil(shown.length / PAGE_SIZE));
  const pageCards = shown.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const selected = protocols && open ? findNdpiProtocol(protocols, open) : undefined;

  const heading = q
    ? `Results for “${q}”`
    : category === ALL
      ? 'All protocols'
      : category === SEEN
        ? 'Seen in your captures'
        : (CATEGORY_LABELS[category] ?? category);
  const seenHere = shown.filter(p => seen.has(p.name)).length;
  const blurb = q
    ? `${shown.length} of ${protocols?.length ?? 0} protocols match.`
    : category === ALL
      ? `The ${protocols?.length ?? 0} protocols and applications nDPI recognises in traffic. ${seen.size} seen in your captures.`
      : category === SEEN
        ? `${seen.size} protocols appear in your captures, the most common first.`
        : `${shown.length} protocols for ${CATEGORY_BLURBS[category] ?? 'this category'}. ${seenHere} seen in your captures.`;

  const pick = (key: string) => update({ category: key === ALL ? null : key, q: null, page: null });

  return (
    <div className="reference-shell">
      <nav className="reference-rail" aria-label="Protocol categories">
        <div className="reference-rail-heading">Categories</div>
        <button type="button" className={`reference-cat${!q && category === ALL ? ' on' : ''}`} onClick={() => pick(ALL)}>
          <span>All protocols</span>
          <span className="reference-cat-count">{protocols?.length ?? ''}</span>
        </button>
        <button type="button" className={`reference-cat${!q && category === SEEN ? ' on' : ''}`} onClick={() => pick(SEEN)}>
          <span>Seen in your captures</span>
          <span className="reference-cat-count">{usage ? seen.size : ''}</span>
        </button>
        <div className="reference-rail-rule" />
        {Object.entries(CATEGORY_LABELS)
          .filter(([key]) => counts[key])
          .sort((a, b) => (a[0] === 'other' ? 1 : b[0] === 'other' ? -1 : (counts[b[0]] ?? 0) - (counts[a[0]] ?? 0)))
          .map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`reference-cat${!q && category === key ? ' on' : ''}`}
              aria-current={!q && category === key ? 'page' : undefined}
              onClick={() => pick(key)}
            >
              <span>{label}</span>
              <span className="reference-cat-count">{counts[key]}</span>
            </button>
          ))}
      </nav>

      <main className="reference-main">
        <div className="reference-head">
          <div>
            <h1 className="reference-title">{heading}</h1>
            <p className="text-muted mb-0">{blurb}</p>
          </div>
          <Form.Control
            type="search"
            className="reference-search"
            placeholder={`Search all ${protocols?.length ?? ''}: name, port, what it does…`}
            aria-label="Search protocols"
            value={q}
            onChange={e => update({ q: e.target.value || null, page: null })}
          />
        </div>

        {!protocols ? (
          <div className="text-muted small py-3">
            <Spinner animation="border" size="sm" className="me-2" />
            Loading…
          </div>
        ) : shown.length === 0 ? (
          <p className="text-muted mt-4">
            {category === SEEN && !q ? 'None of your captures has been analysed yet.' : 'No protocol matches.'}
          </p>
        ) : (
          <>
            <div className="reference-grid">
              {pageCards.map(p => {
                const use = seen.get(p.name);
                return (
                  <button
                    key={p.id}
                    type="button"
                    className={`reference-card${selected?.name === p.name ? ' on' : ''}`}
                    onClick={() => update({ protocol: p.name })}
                  >
                    <span className="reference-card-top">
                      <span className="reference-card-title">{p.title}</span>
                      {use && (
                        <span className="reference-seen" data-testid="protocol-seen">
                          Seen in {use.captures} capture{use.captures === 1 ? '' : 's'}
                        </span>
                      )}
                    </span>
                    <span className="reference-card-code">{p.name}</span>
                    <span className="reference-card-desc">{p.description}</span>
                    <span className="reference-card-evidence">
                      {p.detection.map(d => (
                        <span key={d.type + d.label} className={`reference-ev reference-ev-${d.type}`}>
                          {d.type === 'port' || d.type === 'host' || d.type === 'ip'
                            ? d.label
                            : (DETECTION_LABELS[d.type] ?? d.type)}
                        </span>
                      ))}
                    </span>
                  </button>
                );
              })}
            </div>
            {totalPages > 1 && (
              <Pagination
                currentPage={Math.min(page, totalPages)}
                totalPages={totalPages}
                totalItems={shown.length}
                pageSize={PAGE_SIZE}
                onPageChange={n => update({ page: n > 1 ? String(n) : null })}
                showPageSizeSelector={false}
              />
            )}
          </>
        )}
      </main>

      <SideDrawer
        show={!!selected}
        onHide={() => update({ protocol: null })}
        title={selected?.title ?? ''}
        titleId="protocol-reference-title"
      >
        {selected && <ProtocolDetail protocol={selected} appNames={seen.get(selected.name)?.appNames ?? []} />}
      </SideDrawer>
    </div>
  );
}

/** One protocol's entry: what it is, how nDPI recognises it, where you've seen it, references. */
export function ProtocolDetail({ protocol, appNames }: { protocol: NdpiProtocol; appNames: string[] }) {
  const [captures, setCaptures] = useState<(ProtocolCapture & { appName: string })[] | null>(null);
  const appKey = appNames.join('|');

  useEffect(() => {
    if (!appKey) return;
    let active = true;
    Promise.all(
      appKey.split('|').map(a => protocolUsageService.captures(a).then(cs => cs.map(c => ({ ...c, appName: a }))))
    )
      .then(lists => active && setCaptures(lists.flat().sort((x, y) => y.conversations - x.conversations)))
      .catch(() => active && setCaptures([]));
    return () => {
      active = false;
    };
  }, [appKey]);

  return (
    <div data-testid="protocol-detail">
      <p className="reference-detail-code mb-3">
        {protocol.name} · nDPI ID {protocol.id} · {CATEGORY_LABELS[protocol.category] ?? protocol.category}
      </p>
      <h3 className="reference-detail-heading">What it is</h3>
      <p>{protocol.description}</p>
      {protocol.detection.length > 0 && (
        <>
          <h3 className="reference-detail-heading">How nDPI recognises it</h3>
          <ul className="list-unstyled mb-3">
            {protocol.detection.map(d => (
              <li key={d.type + d.label} className="mb-1">
                <span className={`reference-ev reference-ev-${d.type} me-2`}>{DETECTION_LABELS[d.type] ?? d.type}</span>
                {d.label}
              </li>
            ))}
          </ul>
        </>
      )}
      {protocol.note && <p className="small text-muted">{protocol.note}</p>}
      {appKey && (
        <>
          <h3 className="reference-detail-heading">In your captures</h3>
          {captures == null ? (
            <p className="small text-muted">
              <Spinner animation="border" size="sm" className="me-2" />
              Loading…
            </p>
          ) : (
            <div className="reference-captures mb-3" data-testid="protocol-captures">
              {captures.slice(0, 8).map(c => (
                <Link
                  key={c.fileId + c.appName}
                  to={`/analysis/${c.fileId}/conversations?app=${encodeURIComponent(c.appName)}`}
                  className="reference-capture"
                >
                  <span className="text-truncate">{c.fileName}</span>
                  <span className="text-muted ms-auto text-nowrap">
                    {c.conversations} conversation{c.conversations === 1 ? '' : 's'} ›
                  </span>
                </Link>
              ))}
              {captures.length > 8 && (
                <div className="reference-capture text-muted">+ {captures.length - 8} more</div>
              )}
            </div>
          )}
          <p className="small text-muted">Each opens that capture's conversations, filtered to it.</p>
        </>
      )}
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
