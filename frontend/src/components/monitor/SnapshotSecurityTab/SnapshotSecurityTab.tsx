import { useMemo } from 'react';
import type { GraphEdge } from '@/features/network/types';

/**
 * Absolute security posture of a single snapshot's capture. Aggregates the four analysis-mode
 * security signals already carried on the network edges (Suricata IDS alerts, nDPI flow risks,
 * user custom signatures, detected file types) into grouped rows, each listing the src→dst pairs
 * that exhibited it. This is the "what security-relevant things are in this capture" view, as a
 * complement to the differential Changes tab.
 */

type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

interface SignalRow {
  /** The signal value, e.g. an IDS signature string or an nDPI risk name. */
  value: string;
  /** Distinct "src → dst" flow labels that exhibited this signal. */
  flows: string[];
}

interface SignalSection {
  key: string;
  title: string;
  icon: string;
  severity: Severity;
  /** Explains what this signal means, shown under the section title. */
  blurb: string;
  rows: SignalRow[];
}

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: '#dc3545',
  WARNING: '#fd7e14',
  INFO: '#6c757d',
};

/** Group one signal across all edges: value → sorted distinct flow labels. */
function aggregate(edges: GraphEdge[], pick: (e: GraphEdge) => string[] | undefined): SignalRow[] {
  const byValue = new Map<string, Set<string>>();
  for (const e of edges) {
    const values = pick(e);
    if (!values || values.length === 0) continue;
    const flow = `${e.source} → ${e.target}`;
    for (const v of values) {
      if (!v) continue;
      if (!byValue.has(v)) byValue.set(v, new Set());
      byValue.get(v)!.add(flow);
    }
  }
  return [...byValue.entries()]
    .map(([value, flows]) => ({ value, flows: [...flows].sort() }))
    .sort((a, b) => b.flows.length - a.flows.length || a.value.localeCompare(b.value));
}

interface SnapshotSecurityTabProps {
  edges: GraphEdge[];
  loading: boolean;
}

export const SnapshotSecurityTab = ({ edges, loading }: SnapshotSecurityTabProps) => {
  const sections = useMemo<SignalSection[]>(() => {
    const defs: Omit<SignalSection, 'rows'>[] = [
      {
        key: 'ids',
        title: 'IDS Alerts',
        icon: 'bi-shield-exclamation',
        severity: 'CRITICAL',
        blurb: 'Suricata signature matches against the Emerging Threats ruleset.',
      },
      {
        key: 'risks',
        title: 'Flow Risks',
        icon: 'bi-exclamation-triangle',
        severity: 'WARNING',
        blurb: 'nDPI-detected anomalies — VPNs, self-signed certs, malformed traffic, and more.',
      },
      {
        key: 'sigs',
        title: 'Custom Signatures',
        icon: 'bi-fingerprint',
        severity: 'WARNING',
        blurb: 'Matches against your user-defined signatures.',
      },
      {
        key: 'files',
        title: 'Detected File Types',
        icon: 'bi-file-earmark-binary',
        severity: 'INFO',
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
      </p>
      {sections.map(section => (
        <div key={section.key} className="mb-4">
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
            <div className="table-responsive">
              <table className="table table-sm table-bordered mb-0" style={{ fontSize: '0.82rem' }}>
                <thead className="table-light">
                  <tr>
                    <th style={{ width: '55%' }}>{section.title === 'Detected File Types' ? 'File type' : 'Signal'}</th>
                    <th>Flows</th>
                  </tr>
                </thead>
                <tbody>
                  {section.rows.map(row => (
                    <tr key={row.value}>
                      <td className="font-monospace" style={{ wordBreak: 'break-word' }}>{row.value}</td>
                      <td>
                        {row.flows.map(f => (
                          <div key={f} className="font-monospace text-muted" style={{ fontSize: '0.76rem' }}>{f}</div>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};
