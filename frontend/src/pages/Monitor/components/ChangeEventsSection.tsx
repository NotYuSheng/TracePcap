import { Badge, Button, Card, Form } from '@govtechsg/sgds-react';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { Pagination } from '@/components/common/Pagination';
import { HelpPopover } from './HelpPopover';
import { SEVERITY_FILTERS, useChangeEventFilters } from '../hooks/useChangeEventFilters';

interface ChangeEventsSectionProps {
  changeEvents: ChangeEvent[];
  snapshots: NetworkSnapshot[];
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
}

/** The "Change Events" card: severity/type/reviewed filters, paged event list. */
export const ChangeEventsSection = ({ changeEvents, snapshots, onPatchChange }: ChangeEventsSectionProps) => {
  const {
    severityFilter,
    changeTypeFilter,
    reviewedFilter,
    eventPage,
    setEventPage,
    selectSeverity,
    selectChangeType,
    selectReviewed,
    changeTypes,
    filteredEvents,
    pagedEvents,
    totalEventPages,
    eventPageSize,
  } = useChangeEventFilters(changeEvents);

  return (
    <Card id="sec-changes" className="mb-4 tp-anchor" style={{ overflow: 'hidden' }}>
      <Card.Header className="d-flex justify-content-between align-items-center">
        <h6 className="mb-0">
          <i className="bi bi-activity me-2"></i>Change Events
          {filteredEvents.length > 0 && (
            <Badge bg="secondary" className="ms-2">{filteredEvents.length}</Badge>
          )}
          <HelpPopover
            id="change-events-info"
            title="What's detected"
            buttonTitle="What's detected"
            buttonStyle={{ verticalAlign: 'middle' }}
          >
            <p className="mb-2 text-muted">Changes are compared against the immediately preceding snapshot by capture time. The first snapshot is the baseline and produces no events.</p>
            <ul className="mb-0 ps-3">
              <li className="mb-2">
                <Badge bg="danger" className="me-1">CRITICAL</Badge>
                <code>IP_MAC_DRIFT</code> — IP claimed by a different MAC (potential ARP spoofing)<br />
                <code>GATEWAY_CHANGE</code> — default gateway IP changed
              </li>
              <li className="mb-2">
                <Badge bg="warning" text="dark" className="me-1">WARNING</Badge>
                <code>MAC_ADDED</code> — new device appeared<br />
                <code>IP_MAC_DRIFT</code> — known MAC moved to a new IP (DHCP drift)
              </li>
              <li>
                <Badge bg="info" text="dark" className="me-1">INFO</Badge>
                <code>PROTOCOL_ADDED</code> / <code>APP_ADDED</code> — new layer-7 protocol or app<br />
                <code>ASN_CHANGE</code> — top external peer shifted ISP / ASN<br />
                <code>VPN_DRIFT</code> — VPN usage appeared or disappeared
              </li>
            </ul>
          </HelpPopover>
        </h6>
        <div className="d-flex align-items-center gap-2 flex-wrap">
          {/* Severity pills */}
          <div className="d-flex gap-1">
            {SEVERITY_FILTERS.map(f => (
              <Button
                key={f}
                type="button"
                size="sm"
                variant={
                  severityFilter === f
                    ? f === 'CRITICAL' ? 'danger'
                      : f === 'WARNING' ? 'warning'
                      : f === 'INFO' ? 'info'
                      : 'primary'
                    : 'outline-secondary'
                }
                onClick={() => selectSeverity(f)}
              >
                {f}
              </Button>
            ))}
          </div>
          {/* Change type select */}
          {changeTypes.length > 2 && (
            <Form.Select
              size="sm"
              style={{ width: 'auto' }}
              value={changeTypeFilter}
              onChange={e => selectChangeType(e.target.value)}
            >
              {changeTypes.map(t => (
                <option key={t} value={t}>{t === 'ALL' ? 'All types' : t}</option>
              ))}
            </Form.Select>
          )}
          {/* Reviewed filter */}
          <div className="d-flex gap-1">
            {(['ALL', 'UNREVIEWED', 'REVIEWED'] as const).map(r => (
              <Button
                key={r}
                type="button"
                size="sm"
                variant={reviewedFilter === r ? 'secondary' : 'outline-secondary'}
                onClick={() => selectReviewed(r)}
              >
                {r === 'ALL' ? 'All' : r === 'UNREVIEWED' ? 'Unreviewed' : 'Reviewed'}
              </Button>
            ))}
          </div>
        </div>
      </Card.Header>


      <Card.Body className="p-0">
        {filteredEvents.length === 0 ? (
          <div className="text-muted text-center py-3">
            {changeEvents.length === 0
              ? 'No changes detected yet. Add more snapshots to start change detection.'
              : 'No events match the current filters.'}
          </div>
        ) : (
          <div className="px-3">
            {pagedEvents.map(event => (
              <ChangeEventBadge key={event.id} event={event} snapshots={snapshots} onPatch={onPatchChange} />
            ))}
          </div>
        )}
        {filteredEvents.length > eventPageSize && (
          <div className="border-top pt-2 px-3 pb-2">
            <Pagination
              currentPage={eventPage}
              totalPages={totalEventPages}
              totalItems={filteredEvents.length}
              pageSize={eventPageSize}
              onPageChange={setEventPage}
            />
          </div>
        )}
      </Card.Body>
    </Card>
  );
};
