import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Card } from '@govtechsg/sgds-react';
import { ChangeEventBadge } from '@/components/monitor/ChangeEventBadge/ChangeEventBadge';
import { SnapshotMap } from '@/components/monitor/SnapshotMap';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import type { NetworkAnnotation, NetworkExternalEvent } from '@/features/insights/types/insights.types';
import { formatBytes, formatSpan } from '@/utils/formatters';
import './NetworkTimeline.css';

type Filter = 'all' | 'changes' | 'captures' | 'notes';

interface NetworkTimelineProps {
  networkId: string;
  snapshots: NetworkSnapshot[];
  changeEvents: ChangeEvent[];
  externalEvents: NetworkExternalEvent[];
  annotations: NetworkAnnotation[];
  onPatchChange: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  /** Opens a capture's full detail (security, subnets, insights). */
  onOpenDetails: (snapshot: NetworkSnapshot) => void;
  onAddNote: () => void;
  onAddEvent: () => void;
  onManage: () => void;
}

type Entry =
  | { kind: 'capture'; at: number; snapshot: NetworkSnapshot; index: number }
  | { kind: 'event'; at: number; event: NetworkExternalEvent }
  | { kind: 'note'; at: number; note: NetworkAnnotation };

const when = (ms: number) =>
  new Date(ms).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
const dayOf = (ms: number) => new Date(ms).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
const timeOf = (s: NetworkSnapshot) => new Date(s.startTime ?? s.addedAt).getTime();

/**
 * Everything that happened to the network on one time axis: each capture with the changes it
 * brought, outside events, and notes. Beside it, the network map at the picked capture, compared
 * with the capture before.
 */
export function NetworkTimeline({
  networkId,
  snapshots,
  changeEvents,
  externalEvents,
  annotations,
  onPatchChange,
  onOpenDetails,
  onAddNote,
  onAddEvent,
  onManage,
}: NetworkTimelineProps) {
  const ordered = useMemo(() => [...snapshots].sort((a, b) => a.snapshotOrder - b.snapshotOrder), [snapshots]);
  const [pickedId, setPickedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const picked = ordered.find(s => s.id === pickedId) ?? ordered[ordered.length - 1] ?? null;
  const pickedIndex = picked ? ordered.indexOf(picked) : -1;
  const previous = pickedIndex > 0 ? ordered[pickedIndex - 1] : null;

  const changesBy = useMemo(() => {
    const m = new Map<string, ChangeEvent[]>();
    for (const e of changeEvents) m.set(e.toSnapshotId, [...(m.get(e.toSnapshotId) ?? []), e]);
    return m;
  }, [changeEvents]);
  const notesBy = useMemo(() => {
    const m = new Map<string, NetworkAnnotation[]>();
    for (const n of annotations) if (n.snapshotId) m.set(n.snapshotId, [...(m.get(n.snapshotId) ?? []), n]);
    return m;
  }, [annotations]);

  const entries = useMemo(() => {
    const all: Entry[] = [
      ...ordered.map((snapshot, index) => ({ kind: 'capture' as const, at: timeOf(snapshot), snapshot, index })),
      ...externalEvents.map(event => ({ kind: 'event' as const, at: new Date(event.eventTime).getTime(), event })),
      ...annotations
        .filter(n => !n.snapshotId)
        .map(note => ({ kind: 'note' as const, at: new Date(note.createdAt).getTime(), note })),
    ];
    return all.sort((a, b) => b.at - a.at);
  }, [ordered, externalEvents, annotations]);

  const counts = {
    changes: changeEvents.length,
    captures: ordered.length,
    notes: externalEvents.length + annotations.length,
  };
  const shown = entries.filter(e => {
    if (filter === 'all') return true;
    if (filter === 'captures') return e.kind === 'capture';
    if (filter === 'changes') return e.kind === 'capture' && (changesBy.get(e.snapshot.id)?.length ?? 0) > 0;
    return e.kind !== 'capture' || (notesBy.get(e.snapshot.id)?.length ?? 0) > 0;
  });

  const chip = (key: Filter, label: string, count?: number) => (
    <button
      type="button"
      className={`nt-chip${filter === key ? ' active' : ''}`}
      aria-pressed={filter === key}
      onClick={() => setFilter(key)}
    >
      {label}
      {count !== undefined && <span className="nt-chip-count">{count}</span>}
    </button>
  );

  return (
    <div className="nt">
      <Card className="nt-list-card">
        <div className="nt-list-head">
          <div className="nt-chips" role="group" aria-label="Show">
            {chip('all', 'All')}
            {chip('changes', 'Changes', counts.changes)}
            {chip('captures', 'Captures', counts.captures)}
            {chip('notes', 'Notes and events', counts.notes)}
          </div>
          <div className="nt-actions">
            <Button size="sm" variant="outline-secondary" onClick={onAddNote}>
              <i className="bi bi-sticky me-1" aria-hidden="true" />
              Note
            </Button>
            <Button size="sm" variant="outline-secondary" onClick={onAddEvent}>
              <i className="bi bi-calendar-event me-1" aria-hidden="true" />
              Outside event
            </Button>
            <Button size="sm" variant="link" className="p-0" onClick={onManage}>
              Manage captures
            </Button>
          </div>
        </div>
        <ol className="nt-list">
          {shown.length === 0 && (
            <li className="nt-empty">
              {ordered.length === 0 ? 'Add a capture of this network to start its timeline.' : 'Nothing here for this filter.'}
            </li>
          )}
          {shown.map(e => {
            if (e.kind === 'capture') {
              const s = e.snapshot;
              const changes = changesBy.get(s.id) ?? [];
              const notes = notesBy.get(s.id) ?? [];
              const isPicked = picked?.id === s.id;
              const span =
                s.startTime && s.endTime ? formatSpan(new Date(s.endTime).getTime() - new Date(s.startTime).getTime()) : null;
              return (
                <li key={`c-${s.id}`} className={`nt-entry nt-capture${isPicked ? ' picked' : ''}`}>
                  <button
                    type="button"
                    className="nt-capture-pick"
                    aria-pressed={isPicked}
                    aria-label={`Show ${s.fileName} on the map`}
                    onClick={() => setPickedId(s.id)}
                  >
                    <span className="nt-when">{when(e.at)}</span>
                    <span className="nt-title">{s.fileName}</span>
                    <span className="nt-meta">
                      {[
                        s.packetCount != null && `${s.packetCount.toLocaleString()} packets`,
                        s.totalBytes != null && formatBytes(s.totalBytes),
                        span,
                        e.index === 0 && 'the baseline',
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  </button>
                  {changes.length > 0 && (
                    <div className="nt-changes">
                      {changes.map(c => (
                        <ChangeEventBadge key={c.id} event={c} snapshots={snapshots} onPatch={onPatchChange} />
                      ))}
                    </div>
                  )}
                  {notes.map(n => (
                    <p key={n.id} className="nt-attached-note">
                      <i className="bi bi-sticky me-1" aria-hidden="true" />
                      {n.body}
                    </p>
                  ))}
                  <div className="nt-capture-links">
                    <Button size="sm" variant="link" className="p-0" onClick={() => onOpenDetails(s)}>
                      Details
                    </Button>
                    <Link to={`/analysis/${s.fileId}`}>Open the capture</Link>
                  </div>
                </li>
              );
            }
            if (e.kind === 'event') {
              return (
                <li key={`e-${e.event.id}`} className="nt-entry nt-event">
                  <span className="nt-when">{when(e.at)}</span>
                  <span className="nt-tag">Outside event</span>
                  <span className="nt-title">{e.event.title}</span>
                  {e.event.description && <span className="nt-meta">{e.event.description}</span>}
                </li>
              );
            }
            return (
              <li key={`n-${e.note.id}`} className="nt-entry nt-note">
                <span className="nt-when">{when(e.at)}</span>
                <span className="nt-tag">Note</span>
                <span className="nt-body">{e.note.body}</span>
              </li>
            );
          })}
        </ol>
      </Card>

      <Card className="nt-map-card">
        <Card.Body>
          {picked ? (
            <>
              <div className="nt-map-head">
                <h2 className="nt-map-title">The network on {when(timeOf(picked))}</h2>
                <span className="text-muted small">
                  {previous ? `compared with ${dayOf(timeOf(previous))}` : 'the baseline'}
                </span>
                <div className="nt-map-nav">
                  <Button
                    size="sm"
                    variant="outline-secondary"
                    disabled={pickedIndex <= 0}
                    onClick={() => setPickedId(ordered[pickedIndex - 1].id)}
                    aria-label="Earlier capture"
                  >
                    <i className="bi bi-chevron-left" aria-hidden="true" />
                  </Button>
                  <span className="small text-muted">
                    {pickedIndex + 1} of {ordered.length}
                  </span>
                  <Button
                    size="sm"
                    variant="outline-secondary"
                    disabled={pickedIndex >= ordered.length - 1}
                    onClick={() => setPickedId(ordered[pickedIndex + 1].id)}
                    aria-label="Later capture"
                  >
                    <i className="bi bi-chevron-right" aria-hidden="true" />
                  </Button>
                </div>
              </div>
              <SnapshotMap
                networkId={networkId}
                snapshot={picked}
                previous={previous}
                changeEvents={changeEvents}
                height={520}
              />
            </>
          ) : (
            <p className="text-muted mb-0">The map shows here once the network has a capture.</p>
          )}
        </Card.Body>
      </Card>
    </div>
  );
}
