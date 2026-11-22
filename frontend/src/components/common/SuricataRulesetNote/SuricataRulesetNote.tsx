import { Badge } from '@govtechsg/sgds-react';
import { useSuricataStatus } from '@/features/suricata/useSuricataStatus';

/** "21 Nov 2026" from "2026-11-21". */
function formatDate(iso: string): string {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}

function age(days: number): string {
  if (days <= 0) return 'today';
  if (days === 1) return '1 day old';
  return `${days} days old`;
}

/**
 * Which Suricata ruleset is behind the alerts, and how old it is (#600). A stale ruleset is
 * flagged, because a lack of alerts may then just mean old signatures. Renders nothing until the
 * status has loaded.
 */
export function SuricataRulesetNote({ className }: { className?: string }) {
  const s = useSuricataStatus();
  if (!s) return null;
  const date = s.rulesetDate ? formatDate(s.rulesetDate) : null;
  return (
    <div className={`small text-muted ${className ?? ''}`} data-testid="suricata-ruleset">
      <i className="bi bi-shield-check me-1" aria-hidden="true" />
      Suricata rules: Emerging Threats{s.source === 'imported' ? ', imported' : ''}
      {date ? `, from ${date}` : ''}
      {s.ageDays != null ? ` (${age(s.ageDays)})` : ''}.
      {s.stale && (
        <Badge bg="warning" text="dark" className="ms-1" data-testid="suricata-ruleset-stale">
          Older than {s.staleAfterDays} days: recent threats may be missed
        </Badge>
      )}
      {s.importError && (
        <span className="d-block text-warning-emphasis mt-1" data-testid="suricata-import-error">
          <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
          A newer ruleset in the import folder wasn't used: {s.importError}.
        </span>
      )}
    </div>
  );
}
