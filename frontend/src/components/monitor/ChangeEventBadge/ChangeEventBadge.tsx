import { Spinner } from '@components/common/Spinner/Spinner';
import { useState, useEffect } from 'react';
import { Button, Form } from '@govtechsg/sgds-react';
import { IconTooltip } from '@components/common/IconTooltip';
import type { ChangeEvent, NetworkSnapshot } from '@/features/monitor/types/monitor.types';
import { parseDateTime } from '@/utils/dateUtils';
import { severityHex, severityIcon } from '@/utils/severityColors';
import { describeEvent } from '@/features/monitor/utils/describeChange';

interface ChangeEventBadgeProps {
  event: ChangeEvent;
  snapshots: NetworkSnapshot[];
  onPatch: (eventId: string, patch: { reviewed?: boolean; notes?: string | null }) => Promise<void>;
  /** For a narrow column: no capture line or timestamp, and the text wraps. */
  compact?: boolean;
}


export const ChangeEventBadge = ({ event, snapshots, onPatch, compact = false }: ChangeEventBadgeProps) => {
  const toSnap = snapshots.find(s => s.id === event.toSnapshotId);
  const detectedMs = parseDateTime(event.detectedAt as unknown as string | number[]);
  const formattedTime = new Date(detectedMs).toLocaleString('en-GB');

  const [showNotes, setShowNotes] = useState(false);
  const [draftNotes, setDraftNotes] = useState(event.notes ?? '');
  const [saving, setSaving] = useState(false);
  // Optimistic local state so UI responds immediately
  const [localReviewed, setLocalReviewed] = useState(event.reviewed);
  const [localNotes, setLocalNotes] = useState(event.notes ?? '');

  // Keep local state in sync when the parent refreshes the event from the server
  useEffect(() => { setLocalReviewed(event.reviewed); }, [event.reviewed]);
  useEffect(() => { setLocalNotes(event.notes ?? ''); }, [event.notes]);

  const handleReviewToggle = async () => {
    const next = !localReviewed;
    setLocalReviewed(next);
    setSaving(true);
    try {
      await onPatch(event.id, { reviewed: next });
    } catch {
      setLocalReviewed(!next); // revert on error
    } finally {
      setSaving(false);
    }
  };

  const handleSaveNotes = async () => {
    setSaving(true);
    try {
      await onPatch(event.id, { notes: draftNotes.trim() || null });
      setLocalNotes(draftNotes.trim());
      setShowNotes(false);
    } catch {
      // revert draft to last saved
      setDraftNotes(localNotes);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="py-2 border-bottom">
    <div
      className={`d-flex align-items-start gap-3${localReviewed ? ' opacity-50' : ''}`}
      style={{ transition: 'opacity 0.2s' }}
    >
      <i
        className={`bi ${severityIcon(event.severity)} flex-shrink-0 mt-1`}
        style={{ color: severityHex(event.severity) }}
      />
      <div className="flex-grow-1 min-w-0">
        <div className="text-break" style={{ overflowWrap: 'anywhere' }}>{describeEvent(event)}</div>
        {toSnap && !compact && (
          <small className="text-muted d-block">
            Snapshot {toSnap.snapshotOrder + 1}: {toSnap.fileName}
          </small>
        )}
        {localNotes && !showNotes && (
          <small className="text-muted fst-italic d-block mt-1">
            <i className="bi bi-chat-left-text me-1"></i>{localNotes}
          </small>
        )}
      </div>

      <div className="d-flex align-items-center gap-2 flex-shrink-0">
        {!compact && <small className="text-muted text-nowrap">{formattedTime}</small>}
        <IconTooltip text={showNotes ? 'Hide notes' : (localNotes ? 'Edit notes' : 'Add notes')}>
          <Button
            size="sm"
            variant="link"
            className="p-0 text-muted"
            aria-label={showNotes ? 'Hide notes' : (localNotes ? 'Edit notes' : 'Add notes')}
            onClick={() => { setShowNotes(v => !v); setDraftNotes(localNotes); }}
          >
            <i className={`bi bi-chat-left-text${localNotes ? '-fill' : ''}`}></i>
          </Button>
        </IconTooltip>
        <IconTooltip text={localReviewed ? 'Mark as unreviewed' : 'Mark as reviewed'}>
          <Button
            size="sm"
            variant="link"
            className={`p-0 ${localReviewed ? 'text-success' : 'text-muted'}`}
            aria-label={localReviewed ? 'Mark as unreviewed' : 'Mark as reviewed'}
            onClick={handleReviewToggle}
            disabled={saving}
          >
            <i className={`bi bi-check-circle${localReviewed ? '-fill' : ''}`}></i>
          </Button>
        </IconTooltip>
      </div>
    </div>
    {/* The notes editor gets the row's full width, not the text column beside the buttons. */}
        {showNotes && (
          <div className="mt-2 ms-4">
            <Form.Control
              as="textarea"
              size="sm"
              rows={2}
              placeholder="Add notes…"
              value={draftNotes}
              onChange={e => setDraftNotes(e.target.value)}
              autoFocus
            />
            <div className="d-flex gap-1 mt-1">
              <Button
                size="sm"
                variant="primary"
                onClick={handleSaveNotes}
                disabled={saving}
              >
                {saving ? <Spinner animation="border" size="sm" className="me-1" /> : null}
                Save
              </Button>
              <Button
                size="sm"
                variant="outline-secondary"
                onClick={() => { setShowNotes(false); setDraftNotes(localNotes); }}
                disabled={saving}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
    </div>
  );
};
