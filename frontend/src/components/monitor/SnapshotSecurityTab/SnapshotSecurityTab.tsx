import { useEffect, useMemo, useState } from 'react';
import { Pagination } from '@components/common/Pagination/Pagination';
import type { GraphEdge } from '@/features/network/types';

/**
 * Absolute security posture of a single snapshot's capture. Aggregates the four analysis-mode
 * security signals already carried on the network edges (Suricata IDS alerts, nDPI flow risks,
 * user custom signatures, detected file types) into grouped rows, each listing the src→dst pairs
 * that exhibited it. This is the "what security-relevant things are in this capture" view, as a
 * complement to the differential Changes tab.
 */

type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

/** The conversation-filter query param each signal maps to (see useConversationFilters). */
type FilterParam = 'suricataAlerts' | 'riskTypes' | 'customSignatures' | 'fileTypes';

interface Flow {
  /** Display label "src → dst". */
  label: string;
  /** Source IP — used as the `ip` filter when deep-linking a single flow. */
  src: string;
}

interface SignalRow {
  /** The signal value, e.g. an IDS signature string or an nDPI risk name. */
  value: string;
  /** Distinct flows that exhibited this signal. */
  flows: Flow[];
}

interface SignalSection {
  key: string;
  title: string;
  icon: string;
  severity: Severity;
  /** Which conversation-filter param this signal deep-links through. */
  filterParam: FilterParam;
  /** Explains what this signal means, shown under the section title. */
  blurb: string;
  rows: SignalRow[];
}

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: '#dc3545',
  WARNING: '#fd7e14',
  INFO: '#6c757d',
};

/** Group one signal across all edges: value → distinct flows (deduped by label). */
function aggregate(edges: GraphEdge[], pick: (e: GraphEdge) => string[] | undefined): SignalRow[] {
  const byValue = new Map<string, Map<string, Flow>>();
  for (const e of edges) {
    const values = pick(e);
    if (!values || values.length === 0) continue;
    const label = `${e.source} → ${e.target}`;
    for (const v of values) {
      if (!v) continue;
      if (!byValue.has(v)) byValue.set(v, new Map());
      byValue.get(v)!.set(label, { label, src: e.source });
    }
  }
  return [...byValue.entries()]
    .map(([value, flows]) => ({
      value,
      flows: [...flows.values()].sort((a, b) => a.label.localeCompare(b.label)),
    }))
    .sort((a, b) => b.flows.length - a.flows.length || a.value.localeCompare(b.value));
}

const SECTION_PAGE_SIZE = 10;

/**
 * One signal section (IDS / risks / signatures / files) with its own pagination — each has an
 * independent row count, so they page separately.
 */
function SignalSectionView({
  section,
  buildUrl,
}: {
  section: SignalSection;
  buildUrl: (param: FilterParam, value: string, ip?: string) => string;
}) {
  const [page, setPage] = useState(1);
  const totalPages = Math.ceil(section.rows.length / SECTION_PAGE_SIZE);
  const visibleRows = section.rows.slice((page - 1) * SECTION_PAGE_SIZE, page * SECTION_PAGE_SIZE);

  // Keep the current page in range as the section rows change (e.g. edges refetch).
  useEffect(() => {
    if (page > totalPages && totalPages > 0) setPage(totalPages);
  }, [page, totalPages]);

  return (
    <div className="mb-4">
      <div className="d-flex align-items-center gap-2 mb-1">
        <i className={`bi ${section.icon}`} style={{ color: SEVERITY_COLOR[section.severity] }} />
        <span className="fw-semibold">{section.title}</span>
        <span
          className="badge rounded-pill"
          style={{ fontSize: '0.7rem', background: SEVERITY_COLOR[section.severity], color: '#fff' }}
        >
          {section.rows.length}
        </span>
      </div>
      <p className="text-muted mb-2" style={{ fontSize: '0.78rem' }}>{section.blurb}</p>
      {section.rows.length === 0 ? (
        <p className="text-muted small mb-0 ps-1">None detected.</p>
      ) : (
        <>
          <div className="table-responsive">
            <table className="table table-sm table-bordered mb-0" style={{ fontSize: '0.82rem' }}>
              <thead className="table-light">
                <tr>
                  <th style={{ width: '55%' }}>{section.title === 'Detected File Types' ? 'File type' : 'Signal'}</th>
                  <th>Flows</th>
                </tr>
              </thead>
              <tbody>
                {visibleRows.map(row => (
                  <tr key={row.value}>
                    <td className="font-monospace" style={{ wordBreak: 'break-word' }}>
                      <a
                        href={buildUrl(section.filterParam, row.value)}
                        target="_blank"
                        rel="noopener noreferrer"
                        title="Open matching conversations in analysis mode"
                      >
                        {row.value}
                      </a>
                    </td>
                    <td>
                      {row.flows.map(f => (
                        <div key={f.label} className="font-monospace" style={{ fontSize: '0.76rem' }}>
                          <a
                            href={buildUrl(section.filterParam, row.value, f.src)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted"
                            title={`Open conversations for this signal involving ${f.src}`}
                          >
                            {f.label}
                          </a>
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <Pagination
              currentPage={page}
              totalPages={totalPages}
              totalItems={section.rows.length}
              pageSize={SECTION_PAGE_SIZE}
              onPageChange={setPage}
              showPageSizeSelector={false}
            />
          )}
        </>
      )}
    </div>
  );
}

interface SnapshotSecurityTabProps {
  edges: GraphEdge[];
  loading: boolean;
  /** File backing this snapshot; deep-links jump to its analysis-mode conversation view. */
  fileId: string;
}

export const SnapshotSecurityTab = ({ edges, loading, fileId }: SnapshotSecurityTabProps) => {
  /**
   * Build a deep-link into analysis mode's conversation table, pre-filtered to this signal
   * (and optionally a single source host). The conversation page reads every filter from URL
   * query params, so this lands the analyst on exactly the offending flows.
   */
  const buildUrl = (param: FilterParam, value: string, ip?: string): string => {
    const qs = new URLSearchParams();
    qs.set(param, value);
    if (ip) qs.set('ip', ip);
    return `/analysis/${fileId}/conversations?${qs.toString()}`;
  };

  const sections = useMemo<SignalSection[]>(() => {
    const defs: Omit<SignalSection, 'rows'>[] = [
      {
        key: 'ids',
        title: 'IDS Alerts',
        icon: 'bi-shield-exclamation',
        severity: 'CRITICAL',
        filterParam: 'suricataAlerts',
        blurb: 'Suricata signature matches against the Emerging Threats ruleset.',
      },
      {
        key: 'risks',
        title: 'Flow Risks',
        icon: 'bi-exclamation-triangle',
        severity: 'WARNING',
        filterParam: 'riskTypes',
        blurb: 'nDPI-detected anomalies — VPNs, self-signed certs, malformed traffic, and more.',
      },
      {
        key: 'sigs',
        title: 'Custom Signatures',
        icon: 'bi-fingerprint',
        // CRITICAL to stay consistent with the tab-header badge (SnapshotDetailModal treats
        // signatures as critical) and the backend detectSecurityDrift severity.
        severity: 'CRITICAL',
        filterParam: 'customSignatures',
        blurb: 'Matches against your user-defined signatures.',
      },
      {
        key: 'files',
        title: 'Detected File Types',
        icon: 'bi-file-earmark-binary',
        severity: 'INFO',
        filterParam: 'fileTypes',
        blurb: 'File types carved from transferred content.',
      },
    ];
    const pickers: Record<string, (e: GraphEdge) => string[] | undefined> = {
      ids: e => e.data.suricataAlerts,
      risks: e => e.data.flowRisks,
      sigs: e => e.data.customSignatures,
      files: e => e.data.detectedFileTypes,
    };
    return defs.map(d => ({ ...d, rows: aggregate(edges, pickers[d.key]) }));
  }, [edges]);

  if (loading) {
    return <p className="text-muted small mb-0">Loading capture data…</p>;
  }

  const totalSignals = sections.reduce((n, s) => n + s.rows.length, 0);

  if (totalSignals === 0) {
    return (
      <div className="text-center text-muted py-5">
        <i className="bi bi-shield-check text-success d-block mb-2" style={{ fontSize: '2rem' }} />
        No security signals detected in this capture.
      </div>
    );
  }

  return (
    <div>
      <p className="text-muted small mb-3">
        Security-relevant signals detected in this capture. This is the absolute posture of the
        snapshot; the <strong>Changes</strong> tab shows what is new versus the previous snapshot.
        Click a signal to open the matching conversations in analysis mode, or a flow to also
        filter by that host.
      </p>
      {sections.map(section => (
        <SignalSectionView key={section.key} section={section} buildUrl={buildUrl} />
      ))}
    </div>
  );
};
