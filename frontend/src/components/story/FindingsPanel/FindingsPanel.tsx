import { InfoPopover } from '@components/common/InfoPopover';
import { EscapableOverlayTrigger } from '@components/common/EscapableOverlayTrigger';
import { Badge, Button, Card } from '@govtechsg/sgds-react';
import type { Finding, FindingSeverity } from '@/types';
import { useMemo, useState } from 'react';
import { Pagination } from '@components/common/Pagination/Pagination';
import './FindingsPanel.css';
import { findingBadgeBg, findingBadgeText } from '@/utils/severityColors';

function FindingsInfoPopover() {
  const popover = (
    <InfoPopover
      id="info-findings"
      kind="How it works"
      title="How findings are made"
      source="8 detectors"
      docs="features/story-mode"
      docsAnchor="deterministic-findings"
    >
      <p className="mb-2">
        Computed from every conversation, not by the LLM: <strong>nDPI risks</strong>,{' '}
        <strong>beacons</strong>, <strong>TLS anomalies</strong>, <strong>volume</strong>,{' '}
        <strong>fan-out</strong>, <strong>long sessions</strong>, <strong>unknown apps</strong> and{' '}
        <strong>port mismatches</strong>.
      </p>
      <p className="mb-0">The story is written from these; it can&apos;t add findings of its own.</p>
    </InfoPopover>
  );
  return (
    <EscapableOverlayTrigger trigger="click" placement="left" overlay={popover}>
      <Button
        type="button"
        variant="link"
        className="p-0 text-muted ms-1"
        style={{ lineHeight: 1 }}
        aria-label="About Deterministic Findings"
      >
        <i className="bi bi-info-circle" style={{ fontSize: '0.9rem' }}></i>
      </Button>
    </EscapableOverlayTrigger>
  );
}

const SEVERITY_ORDER: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function severityHeaderClass(severity: FindingSeverity): string {
  switch (severity) {
    case 'CRITICAL':
      return 'text-danger';
    case 'HIGH':
      return 'text-warning';
    case 'MEDIUM':
      return 'text-info';
    case 'LOW':
      return 'text-secondary';
  }
}

interface FindingCardProps {
  finding: Finding;
}

function FindingCard({ finding }: FindingCardProps) {
  const metricEntries = finding.metrics
    ? Object.entries(finding.metrics).filter(([, v]) => v !== null)
    : [];

  return (
    <Card className="mb-2">
      <Card.Body className="py-2 px-3">
        <div className="d-flex align-items-start gap-2 mb-1">
          <Badge
            bg={findingBadgeBg(finding.severity)}
            text={findingBadgeText(finding.severity)}
            style={{ whiteSpace: 'nowrap', fontSize: '0.7rem' }}
          >
            {finding.severity}
          </Badge>
          <h6 className="mb-0 small fw-semibold" style={{ lineHeight: '1.4' }}>
            {finding.title}
          </h6>
        </div>
        <p className="mb-1 small text-muted" style={{ lineHeight: '1.4' }}>
          {finding.summary}
        </p>
        {metricEntries.length > 0 && (
          <div className="d-flex flex-wrap gap-2 mb-1">
            {metricEntries.map(([key, value]) => (
              <span
                key={key}
                className="text-muted"
                style={{ fontSize: '0.72rem', fontFamily: 'monospace' }}
              >
                {key}: <strong>{String(value)}</strong>
              </span>
            ))}
          </div>
        )}
        {finding.affectedIps && finding.affectedIps.length > 0 && (
          <div className="d-flex flex-wrap gap-1">
            {finding.affectedIps.map(ip => (
              <Badge
                key={ip}
                bg="light"
                text="dark"
                className="border"
                style={{ fontSize: '0.7rem', fontFamily: 'monospace' }}
              >
                {ip}
              </Badge>
            ))}
          </div>
        )}
      </Card.Body>
    </Card>
  );
}

interface Props {
  findings: Finding[];
}

export function FindingsPanel({ findings }: Props) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<FindingSeverity | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const counts = SEVERITY_ORDER.reduce<Record<FindingSeverity, number>>(
    (acc, sev) => ({ ...acc, [sev]: findings.filter(f => f.severity === sev).length }),
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  );
  const total = findings.length;

  // Most serious first; the search and the severity chip narrow it, then it is paged.
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...findings]
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .filter(f => !severity || f.severity === severity)
      .filter(
        f =>
          !q ||
          f.title.toLowerCase().includes(q) ||
          f.summary.toLowerCase().includes(q) ||
          f.type.toLowerCase().replace(/_/g, ' ').includes(q) ||
          f.affectedIps.some(ip => ip.toLowerCase().includes(q))
      );
  }, [findings, query, severity]);
  const totalPages = Math.max(1, Math.ceil(shown.length / pageSize));
  const current = Math.min(page, totalPages);
  const pageItems = shown.slice((current - 1) * pageSize, current * pageSize);

  return (
    <Card>
      <Card.Header className="d-flex align-items-center justify-content-between">
        <div className="d-flex align-items-center gap-2">
          <h6 className="mb-0">
            <i className="bi bi-shield-exclamation me-2"></i>
            Deterministic Findings
          </h6>
          <FindingsInfoPopover />
        </div>
        <span className="text-muted small">
          {total} finding{total !== 1 ? 's' : ''}
        </span>
      </Card.Header>
      <Card.Body>
        <div className="findings-tools">
          <input
            type="search"
            className="form-control form-control-sm"
            placeholder="Search findings: a host, a type, a word…"
            aria-label="Search findings"
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setPage(1);
            }}
          />
          <div className="findings-severity" role="group" aria-label="Show findings of one severity">
            <Button
              size="sm"
              variant={severity === null ? 'primary' : 'outline-secondary'}
              aria-pressed={severity === null}
              onClick={() => {
                setSeverity(null);
                setPage(1);
              }}
            >
              All {total}
            </Button>
            {SEVERITY_ORDER.filter(sev => counts[sev] > 0).map(sev => (
              <Button
                key={sev}
                size="sm"
                variant={severity === sev ? 'primary' : 'outline-secondary'}
                aria-pressed={severity === sev}
                onClick={() => {
                  setSeverity(severity === sev ? null : sev);
                  setPage(1);
                }}
              >
                {sev.charAt(0) + sev.slice(1).toLowerCase()} {counts[sev]}
              </Button>
            ))}
          </div>
        </div>
        {pageItems.length === 0 && (
          <p className="text-muted small mb-0">No findings match.</p>
        )}
        {pageItems.map((finding, i) => {
          // A severity heading where the severity changes, so each page still reads in groups.
          const head = i === 0 || pageItems[i - 1].severity !== finding.severity;
          return (
            <div key={`${current}-${i}`}>
              {head && (
                <h6 className={`small fw-bold text-uppercase mb-2 mt-2 ${severityHeaderClass(finding.severity)}`}>
                  {finding.severity} ({counts[finding.severity]})
                </h6>
              )}
              <FindingCard finding={finding} />
            </div>
          );
        })}
        {shown.length > Math.min(10, pageSize) && (
          <Pagination
            currentPage={current}
            totalPages={totalPages}
            totalItems={shown.length}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={n => {
              setPageSize(n);
              setPage(1);
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        )}
      </Card.Body>
    </Card>
  );
}
