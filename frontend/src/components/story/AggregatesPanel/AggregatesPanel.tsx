import { OverlayTrigger, Popover } from '@govtechsg/sgds-react';
import type { StoryAggregates, AsnEntry, ProtocolRiskEntry, BeaconCandidate } from '@/types';

function InfoPopover() {
  const popover = (
    <Popover id="info-aggregates" style={{ maxWidth: '340px' }}>
      <Popover.Header>Traffic Intelligence — How it works</Popover.Header>
      <Popover.Body className="small">
        <p className="mb-2">
          These figures are computed deterministically from <strong>all conversations</strong> in
          the dataset — not just the LLM evidence sample — so they accurately reflect the full
          capture.
        </p>
        <p className="mb-2">
          <strong>Beacon detection</strong> uses a statistical heuristic: flows with ≥ 3 connections
          to the same destination are tested for periodicity using the coefficient of variation (CV)
          of inter-arrival times. A low CV (&lt; 0.1) suggests highly regular, automated traffic.{' '}
          <strong>Limitations:</strong> short captures may produce false positives; legitimate
          software (e.g. NTP, telemetry) can appear beacon-like.
        </p>
        <p className="mb-2">
          <strong>TLS health</strong> is based on certificate issuer metadata extracted during
          analysis. Certificates are not re-validated at display time.
        </p>
        <p className="mb-0">
          <strong>ASN / geo data</strong> is enriched via an external API at analysis time and may
          not reflect recent IP reassignments.
        </p>
      </Popover.Body>
    </Popover>
  );
  return (
    <OverlayTrigger trigger="click" placement="left" overlay={popover} rootClose>
      <button
        type="button"
        className="btn btn-link p-0 text-muted ms-1"
        style={{ lineHeight: 1 }}
        aria-label="About Traffic Intelligence"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }}></i>
      </button>
    </OverlayTrigger>
  );
}

interface Props {
  aggregates: StoryAggregates;
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1_073_741_824) return (bytes / 1_073_741_824).toFixed(1) + ' GB';
  if (bytes >= 1_048_576) return (bytes / 1_048_576).toFixed(1) + ' MB';
  if (bytes >= 1_024) return (bytes / 1_024).toFixed(1) + ' KB';
  return bytes + ' B';
}

function fmtInterval(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}

function CoverageBanner({ aggregates }: { aggregates: StoryAggregates }) {
  const cov = aggregates.coverage;
  const riskTotal = aggregates.protocolRiskMatrix.reduce((s, r) => s + r.atRisk, 0);
  const riskPct =
    cov.totalConversations > 0 ? ((riskTotal / cov.totalConversations) * 100).toFixed(1) : '0.0';

  return (
    <div className="d-flex flex-wrap gap-3 mb-0">
      <div className="text-center px-3">
        <div className="fs-5 fw-semibold">{cov.totalConversations.toLocaleString()}</div>
        <div className="text-muted small">Total Flows</div>
      </div>
      <div className="vr d-none d-md-block" />
      <div className="text-center px-3">
        <div className="fs-5 fw-semibold">{cov.totalPackets.toLocaleString()}</div>
        <div className="text-muted small">Total Packets</div>
      </div>
      <div className="vr d-none d-md-block" />
      <div className="text-center px-3">
        <div
          className={`fs-5 fw-semibold ${Number(riskPct) > 10 ? 'text-danger' : Number(riskPct) > 0 ? 'text-warning' : 'text-success'}`}
        >
          {riskPct}%
        </div>
        <div className="text-muted small">Flows At Risk</div>
      </div>
      <div className="vr d-none d-md-block" />
      <div className="text-center px-3">
        <div className="fs-5 fw-semibold">{aggregates.unknownAppPct.toFixed(1)}%</div>
        <div className="text-muted small">Unknown App</div>
      </div>
      {aggregates.tlsAnomalySummary.total > 0 && (
        <>
          <div className="vr d-none d-md-block" />
          <div className="text-center px-3">
            <div
              className={`fs-5 fw-semibold ${aggregates.tlsAnomalySummary.selfSigned + aggregates.tlsAnomalySummary.expired + aggregates.tlsAnomalySummary.unknownCa > 0 ? 'text-warning' : 'text-success'}`}
            >
              {aggregates.tlsAnomalySummary.selfSigned +
                aggregates.tlsAnomalySummary.expired +
                aggregates.tlsAnomalySummary.unknownCa}
            </div>
            <div className="text-muted small">TLS Anomalies</div>
          </div>
        </>
      )}
    </div>
  );
}

function TopAsnsTable({ entries }: { entries: AsnEntry[] }) {
  if (entries.length === 0)
    return <p className="text-muted small mb-0">No external destinations detected.</p>;

  return (
    <table className="table table-sm table-hover mb-0 small">
      <thead>
        <tr>
          <th>Organisation</th>
          <th className="text-end">Flows</th>
          <th className="text-end">Data</th>
          <th className="text-end">%</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={i}>
            <td>
              {e.country && (
                <span className="badge bg-secondary me-1 fw-normal" style={{ fontSize: '0.7em' }}>
                  {e.country}
                </span>
              )}
              {e.org ?? 'Unknown'}
              {e.asn && (
                <span className="text-muted ms-1" style={{ fontSize: '0.85em' }}>
                  ({e.asn})
                </span>
              )}
            </td>
            <td className="text-end">{e.flowCount.toLocaleString()}</td>
            <td className="text-end">{fmtBytes(e.bytes)}</td>
            <td className="text-end">{e.pct.toFixed(1)}%</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ProtocolRiskTable({ entries }: { entries: ProtocolRiskEntry[] }) {
  if (entries.length === 0) return null;

  return (
    <table className="table table-sm table-hover mb-0 small">
      <thead>
        <tr>
          <th>Protocol</th>
          <th className="text-end">Total</th>
          <th className="text-end">At Risk</th>
          <th style={{ width: '35%' }}></th>
        </tr>
      </thead>
      <tbody>
        {entries.map((e, i) => {
          const pct = e.total > 0 ? (e.atRisk / e.total) * 100 : 0;
          return (
            <tr key={i}>
              <td className="fw-medium">{e.protocol}</td>
              <td className="text-end">{e.total.toLocaleString()}</td>
              <td className={`text-end ${e.atRisk > 0 ? 'text-danger fw-semibold' : 'text-muted'}`}>
                {e.atRisk.toLocaleString()}
              </td>
              <td>
                {e.atRisk > 0 && (
                  <div className="progress" style={{ height: '6px' }}>
                    <div
                      className={`progress-bar ${pct > 30 ? 'bg-danger' : 'bg-warning'}`}
                      style={{ width: `${Math.min(pct, 100)}%` }}
                    />
                  </div>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function TlsBadges({ aggregates }: { aggregates: StoryAggregates }) {
  const tls = aggregates.tlsAnomalySummary;
  if (tls.total === 0)
    return <p className="text-muted small mb-0">No TLS conversations detected.</p>;

  const anomalies = tls.selfSigned + tls.expired + tls.unknownCa;
  if (anomalies === 0) {
    return (
      <span className="badge bg-success">
        <i className="bi bi-shield-check me-1" />
        All {tls.total} TLS flows OK
      </span>
    );
  }

  return (
    <div className="d-flex flex-wrap gap-2 align-items-center">
      <span className="text-muted small">{tls.total} TLS flows —</span>
      {tls.selfSigned > 0 && (
        <span className="badge bg-warning text-dark">{tls.selfSigned} self-signed</span>
      )}
      {tls.expired > 0 && <span className="badge bg-danger">{tls.expired} expired</span>}
      {tls.unknownCa > 0 && (
        <span className="badge bg-secondary">{tls.unknownCa} unknown issuer</span>
      )}
    </div>
  );
}

function BeaconList({ candidates }: { candidates: BeaconCandidate[] }) {
  if (candidates.length === 0)
    return <p className="text-muted small mb-0">No beacon-like patterns detected.</p>;

  return (
    <div className="d-flex flex-column gap-2">
      {candidates.map((b, i) => (
        <div key={i} className="d-flex align-items-start gap-2 small">
          <span
            className="badge bg-danger mt-1"
            style={{ minWidth: '1.5rem', textAlign: 'center' }}
          >
            {i + 1}
          </span>
          <div>
            <span className="fw-medium font-monospace">
              {b.srcIp} → {b.dstIp ?? '?'}:{b.dstPort ?? '*'}
            </span>
            {b.appName && <span className="badge bg-light text-dark ms-1 border">{b.appName}</span>}
            <div className="text-muted">
              {b.protocol} &middot; {b.flowCount} flows &middot; avg&nbsp;
              <span className="fw-medium">{fmtInterval(b.avgIntervalMs)}</span>
              &nbsp;&middot; jitter&nbsp;
              <span className={`fw-medium ${b.cv < 0.1 ? 'text-danger' : 'text-warning'}`}>
                {(b.cv * 100).toFixed(1)}%
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export const AggregatesPanel = ({ aggregates }: Props) => {
  const hasBeacons = aggregates.beaconCandidates.length > 0;
  const hasTlsAnomalies =
    aggregates.tlsAnomalySummary.selfSigned +
      aggregates.tlsAnomalySummary.expired +
      aggregates.tlsAnomalySummary.unknownCa >
    0;

  return (
    <div className="card mb-4">
      <div className="card-header d-flex align-items-center gap-2">
        <i className="bi bi-bar-chart-line text-primary" />
        <h6 className="mb-0 d-flex align-items-center">
          Traffic Intelligence — Full Dataset
          <InfoPopover />
        </h6>
        {(hasBeacons || hasTlsAnomalies) && (
          <span className="badge bg-danger ms-auto">Findings</span>
        )}
      </div>
      <div className="card-body">
        {/* Coverage banner */}
        <CoverageBanner aggregates={aggregates} />

        <hr className="my-3" />

        <div className="row g-4">
          {/* Top External ASNs */}
          <div className="col-lg-6">
            <h6 className="text-muted text-uppercase small fw-semibold mb-2 letter-spacing-1">
              Top External Destinations
            </h6>
            <TopAsnsTable entries={aggregates.topExternalAsns} />
          </div>

          {/* Protocol × Risk Matrix */}
          <div className="col-lg-6">
            <h6 className="text-muted text-uppercase small fw-semibold mb-2">
              Protocol Risk Overview
            </h6>
            <ProtocolRiskTable entries={aggregates.protocolRiskMatrix} />
          </div>

          {/* TLS Anomalies */}
          <div className="col-lg-6">
            <h6 className="text-muted text-uppercase small fw-semibold mb-2">
              TLS Certificate Health
            </h6>
            <TlsBadges aggregates={aggregates} />
          </div>

          {/* Beacon Candidates */}
          <div className="col-lg-6">
            <h6 className="text-muted text-uppercase small fw-semibold mb-2 d-flex align-items-center gap-2">
              Beacon Candidates
              {hasBeacons && (
                <span className="badge bg-danger fw-normal">
                  {aggregates.beaconCandidates.length}
                </span>
              )}
            </h6>
            <BeaconList candidates={aggregates.beaconCandidates} />
          </div>
        </div>
      </div>
    </div>
  );
};
